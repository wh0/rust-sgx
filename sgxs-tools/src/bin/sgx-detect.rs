extern crate sgxs;
extern crate aesm_client;
extern crate sgx_isa;
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate byteorder;

use std::arch::x86_64::{self, CpuidResult};
use std::path::PathBuf;
use std::io;

use byteorder::LE;
use failure::Error;

use aesm_client::AesmClient;
use sgx_isa::{AttributesFlags, Miscselect};

#[derive(Debug, Fail)]
enum DetectError {
	#[fail(display = "CPUID leaf {:x}h is not valid", leaf)]
	CpuidLeafInvalid { leaf: u32 },
	#[fail(display = "Failed access EFI variables: {}", _0)]
	EfiFsError(io::Error),
	#[fail(display = "Failed to read EFI variable: {}", _0)]
	EfiVariableError(io::Error),
}

fn cpuid(eax: u32, ecx: u32) -> Result<CpuidResult, Error> {
	unsafe {
		if eax <= x86_64::__get_cpuid_max(0).0 {
			Ok(x86_64::__cpuid_count(eax, ecx))
		} else {
			bail!(DetectError::CpuidLeafInvalid { leaf: eax })
		}
	}
}

/// Interpreting raw values returned from the environment
mod interpret {
	use super::*;

	use byteorder::ReadBytesExt;

	fn check_bit_32(mut value: u32, bit: u8) -> bool {
		check_bit_erase_32(&mut value, bit)
	}

	fn check_bit_erase_32(value: &mut u32, bit: u8) -> bool {
		let bit = 1 << bit;
		let ret = (*value & bit) != 0;
		if ret {
			*value ^= bit;
		}
		ret
	}

	fn check_bit_64(value: u64, bit: u8) -> bool {
		(value & (1 << bit)) != 0
	}

	#[derive(Debug)]
	pub struct Cpuid7h {
		pub sgx: bool,
		pub sgx_lc: bool,
	}

	impl From<CpuidResult> for Cpuid7h {
		fn from(v: CpuidResult) -> Self {
			// See Intel SDM, Volume 2, Chapter 3, “CPUID”, Leaf 07h
			Cpuid7h {
				sgx: check_bit_32(v.ebx, 2),
				sgx_lc: check_bit_32(v.ecx, 30),
			}
		}
	}

	#[derive(Debug)]
	pub struct Cpuid12h0 {
		pub sgx1: bool,
		pub sgx2: bool,
		pub enclv: bool,
		pub oversub: bool,
		pub kss: bool,
		pub miscselect_valid: Miscselect,
		pub max_enclave_size_32: u64,
		pub max_enclave_size_64: u64
	}

	impl From<CpuidResult> for Cpuid12h0 {
		fn from(mut v: CpuidResult) -> Self {
			// See Intel SDM, Volume 3, Chapter 36, Section 7, “Discovering Support for Intel SGX”
			let ret = Cpuid12h0 {
				sgx1: check_bit_erase_32(&mut v.eax, 0),
				sgx2: check_bit_erase_32(&mut v.eax, 1),
				enclv: check_bit_erase_32(&mut v.eax, 5),
				oversub: check_bit_erase_32(&mut v.eax, 6),
				kss: check_bit_erase_32(&mut v.eax, 7),
				miscselect_valid: Miscselect::from_bits_truncate(v.ebx),
				max_enclave_size_32: 1 << (v.edx as u8),
				max_enclave_size_64: 1 << ((v.edx >> 8) as u8),
			};
			if v.eax != 0 {
				warn!("CPUID 12h, sub-leaf 0 EAX has reserved bits set: {:08x}", v.eax);
			}
			if (v.ebx ^ ret.miscselect_valid.bits()) != 0 {
				warn!("CPUID 12h, sub-leaf 0 EBX (MISCSELECT) has reserved bits set: {:08x}", v.ebx ^ ret.miscselect_valid.bits());
			}
			if v.ecx != 0 {
				warn!("CPUID 12h, sub-leaf 0 ECX has reserved bits set: {:08x}", v.ecx);
			}
			if (v.edx & !0xffff) != 0 {
				warn!("CPUID 12h, sub-leaf 0 EDX has reserved bits set: {:08x}", v.edx & !0xffff);
			}
			ret
		}
	}

	#[derive(Debug)]
	pub struct Cpuid12h1 {
		pub attributes_flags_valid: AttributesFlags,
		pub attributes_xfrm_valid: u64,
	}

	impl From<CpuidResult> for Cpuid12h1 {
		fn from(v: CpuidResult) -> Self {
			// See Intel SDM, Volume 3, Chapter 36, Section 7, “Discovering Support for Intel SGX”
			let attributes_flags = (v.eax as u64) | ((v.ebx as u64) << 32);
			let ret = Cpuid12h1 {
				attributes_flags_valid: AttributesFlags::from_bits_truncate(attributes_flags),
				attributes_xfrm_valid: (v.ecx as u64) | ((v.edx as u64) << 32),
			};
			if (attributes_flags ^ ret.attributes_flags_valid.bits()) != 0 {
				warn!("CPUID 12h, sub-leaf 1 EBX:EAX (ATTRIBUTES.FLAGS) has reserved bits set: {:016x}", attributes_flags ^ ret.attributes_flags_valid.bits());
			}
			ret
		}
	}

	#[derive(Debug)]
	pub enum EpcType {
		Invalid,
		ConfidentialityIntegrityProtected,
		Unknown
	}

	#[derive(Debug)]
	pub enum Cpuid12hEnum {
		Invalid,
		Epc {
			ty: EpcType,
			phys_base: u64,
			phys_size: u64,
		},
		Unknown
	}

	impl From<(u32, CpuidResult)> for Cpuid12hEnum {
		fn from((subleaf, v): (u32, CpuidResult)) -> Self {
			// See Intel SDM, Volume 3, Chapter 36, Section 7, “Discovering Support for Intel SGX”
			match v.eax & 0xf {
				0 => Cpuid12hEnum::Invalid,
				1 => { // EPC section
					// SDM documentation somewhat unclear on this field (referring to EAX[3:0])
					let ty = match v.ecx & 0xf {
						0 => EpcType::Invalid,
						1 => EpcType::ConfidentialityIntegrityProtected,
						n => {
							warn!("CPUID 12h, sub-leaf {} (EPC section) unknown EPC type: {:x}h. EAX={:08x}, EBX={:08x}, ECX={:08x}, EDX={:08x}", subleaf, n, v.eax, v.ebx, v.ecx, v.edx);
							EpcType::Unknown
						},
					};
					let ret = Cpuid12hEnum::Epc {
						ty,
						phys_base: ((v.ebx as u64 & 0xf_fffff) << 32) | (v.eax as u64 & 0xffff_f000),
						phys_size: ((v.edx as u64 & 0xf_fffff) << 32) | (v.ecx as u64 & 0xffff_f000),
					};
					if (v.eax & 0xff0) != 0 {
						warn!("CPUID 12h, sub-leaf {} EAX has reserved bits set: {:08x}", subleaf, v.eax & 0xff0);
					}
					if (v.ebx & 0xfff0_0000) != 0 {
						warn!("CPUID 12h, sub-leaf {} EBX has reserved bits set: {:08x}", subleaf, v.ebx & 0xfff0_0000);
					}
					if (v.ecx & 0xff0) != 0 {
						warn!("CPUID 12h, sub-leaf {} ECX has reserved bits set: {:08x}", subleaf, v.ecx & 0xff0);
					}
					if (v.edx & 0xfff0_0000) != 0 {
						warn!("CPUID 12h, sub-leaf {} EDX has reserved bits set: {:08x}", subleaf, v.edx & 0xfff0_0000);
					}
					ret
				},
				n => {
					warn!("CPUID 12h, sub-leaf {} unknown section type: {:x}h. EAX={:08x}, EBX={:08x}, ECX={:08x}, EDX={:08x}", subleaf, n, v.eax, v.ebx, v.ecx, v.edx);
					Cpuid12hEnum::Unknown
				}
			}
		}
	}

	#[derive(Debug)]
	pub struct Msr3ah {
		pub locked: bool,
		pub sgx: bool,
		pub sgx_lc: bool,
	}

	impl From<u64> for Msr3ah {
		fn from(v: u64) -> Self {
			// See Intel SDM, Volume 4, Chapter 2, Section 1, “Architectural MSRs”, Address 3Ah
			Msr3ah {
				locked: check_bit_64(v, 0),
				sgx_lc: check_bit_64(v, 17),
				sgx: check_bit_64(v, 18),
			}
		}
	}

	#[derive(Debug, Default)]
	pub struct EfiEpcbios {
		prm_bins: u32,
		max_epc_size: u32,
		current_epc_size: u32,
		epc_map: [u32; 32],
	}

	impl From<Vec<u8>> for EfiEpcbios {
		fn from(v: Vec<u8>) -> Self {
			if v.len() != std::mem::size_of::<Self>() {
				warn!("Invalid size for EPCBIOS EFI variable: {}", v.len());
			}
			let mut v = &v[..];
			(|| -> Result<_, io::Error> { Ok(
				EfiEpcbios {
					prm_bins: v.read_u32::<LE>()?,
					max_epc_size: v.read_u32::<LE>()?,
					current_epc_size: v.read_u32::<LE>()?,
					epc_map: {
						let mut map = [0u32; 32];
						for elem in &mut map {
							*elem = v.read_u32::<LE>()?;
						}
						map
					}
				}
			) } )().unwrap_or_default()
		}
	}

	#[derive(Debug, Default)]
	pub struct EfiEpcsw {
		epc_size: u32,
	}

	impl From<Vec<u8>> for EfiEpcsw {
		fn from(v: Vec<u8>) -> Self {
			if v.len() != std::mem::size_of::<Self>() {
				warn!("Invalid size for EPCSW EFI variable: {}", v.len());
			}
			let mut v = &v[..];
			(|| -> Result<_, io::Error> { Ok(
				EfiEpcsw {
					epc_size: v.read_u32::<LE>()?,
				}
			) } )().unwrap_or_default()
		}
	}

	#[derive(Debug)]
	pub enum SgxEnableStatus {
		Disabled,
		Enabled,
		SoftwareControlled,
		Unknown
	}

	#[derive(Debug)]
	pub struct EfiSoftwareguardstatus {
		status: SgxEnableStatus,
	}

	impl From<Vec<u8>> for EfiSoftwareguardstatus {
		fn from(v: Vec<u8>) -> Self {
			if v.len() != std::mem::size_of::<Self>() {
				warn!("Invalid size for SOFTWAREGUARDSTATUS EFI variable: {}", v.len());
			}
			let status = v.get(0).map(|v| v & 0b11);
			let reserved = v.get(0).map(|v| v & !0b11);
			let ret = EfiSoftwareguardstatus {
				status: match status {
					Some(0) => SgxEnableStatus::Disabled,
					Some(1) => SgxEnableStatus::Enabled,
					Some(2) => SgxEnableStatus::SoftwareControlled,
					Some(v) => {
						warn!("EFI variable SOFTWAREGUARDSTATUS: invalid status {:x}", v);
						SgxEnableStatus::Unknown
					},
					None => SgxEnableStatus::Unknown,
				}
			};
			match reserved {
				None | Some(0) => {},
				Some(v) => warn!("EFI variable SOFTWAREGUARDSTATUS: invalid reserved bits: {:x}", v)
			}
			ret
		}
	}

}

mod linux {
	use super::*;

	use std::fs::File;
	use std::ffi::OsString;
	use std::io::{ErrorKind, Seek, SeekFrom, Read, BufReader, BufRead};
	use std::os::unix::ffi::OsStringExt;
	use std::path::PathBuf;
	use std::process::Command;

	use byteorder::ReadBytesExt;
	use failure::{Fail, ResultExt};

	pub fn rdmsr(address: u64) -> Result<u64, Error> {
		fn modprobe_msr() -> Result<(), Error> {
			let output =
				Command::new("modprobe").arg("msr").output()
				.context("Failed executing modprobe")?;
			match output.status.success() {
				true => Ok(()),
				false => bail!("{}", String::from_utf8_lossy(&output.stderr).trim_end())
			}
		}

		let mut attempt = 0;
		loop {
			attempt += 1;
			let file = File::open("/dev/cpu/0/msr");
			match file {
				Ok(mut f) => {
					f.seek(SeekFrom::Start(address)).context("Failed to read MSR")?;
					return f.read_u64::<LE>().context("Failed to read MSR").map_err(Into::into)
				}
				Err(ref e) if attempt == 1 && e.kind() == ErrorKind::NotFound => {
					modprobe_msr().context("Failed to load MSR kernel module")?;
					continue
				}
				Err(e) => bail!(e.context("Failed to open MSR device")),
			}
		}
	}

	pub fn read_efi_var(name: &str, guid: &str) -> Result<Vec<u8>, Error> {
		let fspath = (|| {
			for line in BufReader::new(File::open("/proc/self/mountinfo")?).split(b'\n') {
				let line = line?;
				let mut mountinfo = line.split(|&c| c == b' ');
				if let Some(path) = mountinfo.nth(4) {
					let fs = mountinfo.skip(1).skip_while(|&i| i != b"-").nth(1);
					if fs == Some(b"efivarfs") {
						return Ok(PathBuf::from(OsString::from_vec(path.into())))
					}
				}
			}
			Err(ErrorKind::NotFound.into())
		})().map_err(|e| Error::from(DetectError::EfiFsError(e)) )?;

		(|| {
			let mut file = File::open(fspath.join(&format!("{}-{}", name, guid)))?;
			let mut buf = [0u8; 4];
			file.read_exact(&mut buf)?; // skip EFI attributes
			let mut buf = vec![];
			file.read_to_end(&mut buf)?;
			Ok(buf)
		})().map_err(|e| DetectError::EfiVariableError(e).into())
	}
}

use crate::interpret::*;

#[derive(Debug)]
struct SgxSupport {
	cpuid_7h: Result<Cpuid7h, Error>,
	cpuid_12h_0: Result<Cpuid12h0, Error>,
	cpuid_12h_1: Result<Cpuid12h1, Error>,
	cpuid_12h_epc: Result<Vec<Cpuid12hEnum>, Error>,
	msr_3ah: Result<Msr3ah, Error>,
	efi_epcbios: Result<EfiEpcbios, Error>,
	efi_epcsw: Result<EfiEpcsw, Error>,
	efi_softwareguardstatus: Result<EfiSoftwareguardstatus, Error>,
	aesm_client: Result<AesmClient, Error>,
	dcap_library: Result<PathBuf, Error>,
	sgx_device: Result<PathBuf, Error>,
}

impl SgxSupport {
	fn detect() -> Self {
		let cpuid_7h = cpuid(0x7, 0).map(Cpuid7h::from);
		let cpuid_12h_0 = cpuid(0x12, 0).map(Cpuid12h0::from);
		let cpuid_12h_1 = cpuid(0x12, 1).map(Cpuid12h1::from);
		let cpuid_12h_epc = (2..)
				.into_iter()
				.map(|n| cpuid(0x12, n).map(|v| Cpuid12hEnum::from((n, v))))
				.take_while( |v| match v {
					Err(_) | Ok(Cpuid12hEnum::Invalid) => false,
					_ => true
				})
				.collect();
		let msr_3ah = linux::rdmsr(0x3a).map(Msr3ah::from);
		let efi_epcbios =
			linux::read_efi_var("EPCBIOS", "c60aa7f6-e8d6-4956-8ba1-fe26298f5e87")
			.map(EfiEpcbios::from);
		let efi_epcsw =
			linux::read_efi_var("EPCSW", "d69a279b-58eb-45d1-a148-771bb9eb5251")
			.map(EfiEpcsw::from);
		let efi_softwareguardstatus =
			linux::read_efi_var("SOFTWAREGUARDSTATUS", "9cb2e73f-7325-40f4-a484-659bb344c3cd")
			.map(EfiSoftwareguardstatus::from);
		let aesm_client = (|| {
			let client = AesmClient::new();
			client.try_connect()?;
			Ok(client)
		})();

		SgxSupport {
			cpuid_7h,
			cpuid_12h_0,
			cpuid_12h_1,
			cpuid_12h_epc,
			msr_3ah,
			efi_epcbios,
			efi_epcsw,
			efi_softwareguardstatus,
			aesm_client,
			dcap_library: Err(format_err!("not implemented")),
			sgx_device: Err(format_err!("not implemented")),
		}
	}
}

fn main() {
	env_logger::init();
	println!("{:#?}", SgxSupport::detect());
}
