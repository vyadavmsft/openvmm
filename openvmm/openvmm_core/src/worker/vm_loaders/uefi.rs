// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::worker::memory_layout::ChipsetMmioRanges;
use guestmem::GuestMemory;
use guid::Guid;
use hvdef::HV_PAGE_SIZE;
use loader::importer::Register;
use loader::uefi::IMAGE_SIZE;
use loader::uefi::config;
use openvmm_defs::config::UefiConsoleMode;
use std::io::Read;
use std::io::Seek;
use thiserror::Error;
use vm_loader::Loader;
use vm_topology::memory::MemoryLayout;
use vm_topology::pcie::PcieHostBridge;
use vm_topology::processor::ProcessorTopology;
use zerocopy::IntoBytes;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read uefi firmware file")]
    Firmware(#[source] std::io::Error),
    #[error("uefi loader error")]
    Loader(#[source] loader::uefi::Error),
    #[error("failed to build PCIe ACPI tables")]
    PcieAcpi(#[source] vmm_core::acpi_builder::PcieAcpiBuildError),
    #[cfg(guest_arch = "aarch64")]
    #[error("UEFI boot with GICv2 is not supported")]
    GicV2NotSupported,
}

pub struct UefiLoadSettings {
    pub debugging: bool,
    pub battery: bool,
    pub memory_protections: bool,
    pub frontpage: bool,
    pub tpm: bool,
    pub guest_watchdog: bool,
    pub vpci_boot: bool,
    pub serial: bool,
    pub uefi_console_mode: Option<UefiConsoleMode>,
    pub default_boot_always_attempt: bool,
    pub bios_guid: Guid,
    /// Whether VMBus is present in this VM. When `false`, the firmware's
    /// `vmbus_disabled` flag is set; the `MmioRanges` blob is still provided
    /// but the high MMIO range will be empty. The firmware must support this
    /// mode.
    pub vmbus: bool,
    /// Force UEFI to bounce-buffer all DMA traffic.
    pub force_dma_bounce: bool,
}

/// All inputs needed by [`load_uefi`].
pub struct LoadUefiParams<'a> {
    pub firmware: &'a std::fs::File,
    pub gm: &'a GuestMemory,
    pub processor_topology: &'a ProcessorTopology,
    pub mem_layout: &'a MemoryLayout,
    pub pcie_host_bridges: &'a [PcieHostBridge],
    pub settings: UefiLoadSettings,
    pub chipset_mmio: &'a ChipsetMmioRanges,
    pub acpi_tables: &'a [&'a [u8]],
}

fn add_acpi_table(cfg: &mut config::Blob, table: &[u8]) {
    cfg.add_raw(acpi_table_structure_type(table), table);
}

#[cfg(guest_arch = "x86_64")]
#[allow(deprecated)]
fn acpi_table_structure_type(table: &[u8]) -> config::BlobStructureType {
    match table.get(..4) {
        // The x86 firmware uses the typed MCFG blob to learn the ECAM base for
        // its own PCI enumeration. Keep using generic AcpiTable for other ACPI
        // tables unless the firmware consumes a legacy blob ID directly.
        Some(b"MCFG") => config::BlobStructureType::Mcfg,
        Some(b"SSDT") => config::BlobStructureType::Ssdt,
        _ => config::BlobStructureType::AcpiTable,
    }
}

#[cfg(not(guest_arch = "x86_64"))]
fn acpi_table_structure_type(_table: &[u8]) -> config::BlobStructureType {
    config::BlobStructureType::AcpiTable
}

/// Loads the UEFI firmware.
pub fn load_uefi(params: &LoadUefiParams<'_>) -> Result<Vec<Register>, Error> {
    let LoadUefiParams {
        firmware,
        gm,
        processor_topology,
        mem_layout,
        pcie_host_bridges,
        ref settings,
        chipset_mmio,
        acpi_tables,
    } = *params;

    let mut loaded_image;
    let mut firmware = firmware;
    let image = {
        loaded_image = Vec::new();
        firmware.rewind().map_err(Error::Firmware)?;
        firmware
            .read_to_end(&mut loaded_image)
            .map_err(Error::Firmware)?;
        loaded_image.as_slice()
    };

    let mut entropy = [0; 64];
    getrandom::fill(&mut entropy).expect("rng failure");

    let memory_map: Vec<_> = mem_layout
        .ram()
        .iter()
        .map(|range| config::MemoryRangeV5 {
            base_address: range.range.start(),
            length: range.range.len(),
            flags: 0,
            reserved: 0,
        })
        .collect();

    let flags = config::Flags::new()
        .with_hibernate_enabled(true)
        .with_serial_controllers_enabled(settings.serial)
        .with_vpci_boot_enabled(settings.vpci_boot)
        .with_debugger_enabled(settings.debugging)
        .with_virtual_battery_enabled(settings.battery)
        .with_disable_frontpage(!settings.frontpage)
        .with_tpm_enabled(settings.tpm)
        .with_measure_additional_pcrs(settings.tpm)
        .with_tpm_locality_regs_enabled(settings.tpm)
        .with_watchdog_enabled(settings.guest_watchdog)
        // OpenVMM pre-sets the MTRRs; tell the firmware
        .with_mtrrs_initialized_at_load(true)
        // TODO: plumb all 4 kinds of memory protection modes through
        .with_memory_protection(if settings.memory_protections {
            config::MemoryProtection::Default
        } else {
            config::MemoryProtection::Disabled
        })
        .with_console(
            match settings
                .uefi_console_mode
                .unwrap_or(UefiConsoleMode::Default)
            {
                UefiConsoleMode::Default => config::ConsolePort::Default,
                UefiConsoleMode::Com1 => config::ConsolePort::Com1,
                UefiConsoleMode::Com2 => config::ConsolePort::Com2,
                UefiConsoleMode::None => config::ConsolePort::None,
            },
        )
        .with_default_boot_always_attempt(settings.default_boot_always_attempt)
        .with_vmbus_disabled(!settings.vmbus)
        .with_pci_resources_pre_assigned(true)
        .with_force_dma_bounce_enabled(settings.force_dma_bounce);

    let mut cfg = config::Blob::new();
    cfg.add(&config::BiosInformation {
        bios_size_pages: (IMAGE_SIZE / HV_PAGE_SIZE) as u32,
        flags: 0,
    })
    .add_raw(config::BlobStructureType::MemoryMap, memory_map.as_bytes())
    .add(&config::BiosGuid(settings.bios_guid))
    .add(&config::Entropy(entropy))
    .add(&config::MmioRanges([
        config::Mmio {
            mmio_page_number_start: chipset_mmio.low.start() / HV_PAGE_SIZE,
            mmio_size_in_pages: chipset_mmio.low.len() / HV_PAGE_SIZE,
        },
        config::Mmio {
            mmio_page_number_start: chipset_mmio.high.start() / HV_PAGE_SIZE,
            mmio_size_in_pages: chipset_mmio.high.len() / HV_PAGE_SIZE,
        },
    ]))
    .add(&config::ProcessorInformation {
        max_processor_count: processor_topology.vp_count(),
        processor_count: processor_topology.vp_count(),
        processors_per_virtual_socket: processor_topology.reserved_vps_per_socket(),
        threads_per_processor: if processor_topology.smt_enabled() {
            2
        } else {
            1
        },
    })
    .add(&flags);

    #[cfg(guest_arch = "aarch64")]
    {
        let redistributors_base = match processor_topology.gic_version() {
            vm_topology::processor::aarch64::GicVersion::V3 {
                redistributors_base,
            } => redistributors_base,
            vm_topology::processor::aarch64::GicVersion::V2 { .. } => {
                return Err(Error::GicV2NotSupported);
            }
        };
        cfg.add(&config::Gic {
            gic_distributor_base: processor_topology.gic_distributor_base(),
            gic_redistributors_base: redistributors_base,
        });
    }

    for table in acpi_tables {
        add_acpi_table(&mut cfg, table);
    }

    if !pcie_host_bridges.is_empty() {
        let pcie_tables = vmm_core::acpi_builder::build_pcie_acpi_tables(pcie_host_bridges)
            .map_err(Error::PcieAcpi)?;
        add_acpi_table(&mut cfg, &pcie_tables.ssdt);
        if let Some(cedt) = pcie_tables.cedt {
            cfg.add_raw(config::BlobStructureType::AcpiTable, &cedt);
        }
    }

    if !pcie_host_bridges.is_empty() {
        let entries: Vec<config::PcieBarApertureEntry> = pcie_host_bridges
            .iter()
            .map(|b| config::PcieBarApertureEntry {
                segment: b.segment,
                start_bus: b.start_bus,
                end_bus: b.end_bus,
                uid: b.index,
                low_mmio_base: b.low_mmio.start(),
                low_mmio_length: b.low_mmio.len(),
                high_mmio_base: b.high_mmio.start(),
                high_mmio_length: b.high_mmio.len(),
            })
            .collect();
        cfg.add_raw(
            config::BlobStructureType::PcieBarApertures,
            entries.as_bytes(),
        );
    }

    let mut loader = Loader::new(gm.clone(), mem_layout, hvdef::Vtl::Vtl0);

    loader::uefi::load(
        &mut loader,
        image,
        loader::uefi::ConfigType::ConfigBlob(cfg),
    )
    .map_err(Error::Loader)?;

    Ok(loader.initial_regs())
}

#[cfg(all(test, guest_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn classify_x86_firmware_consumed_acpi_tables() {
        assert_eq!(
            acpi_table_structure_type(b"MCFGtest") as u32,
            config::BlobStructureType::Mcfg as u32
        );
        assert_eq!(
            acpi_table_structure_type(b"SSDTtest") as u32,
            config::BlobStructureType::Ssdt as u32
        );
        assert_eq!(
            acpi_table_structure_type(b"APICtest") as u32,
            config::BlobStructureType::AcpiTable as u32
        );
        assert_eq!(
            acpi_table_structure_type(b"") as u32,
            config::BlobStructureType::AcpiTable as u32
        );
    }
}
