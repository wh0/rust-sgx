/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate enclave_runner;
extern crate failure;
extern crate sgx_isa;
extern crate sgxs;

use failure::{Error, ResultExt};

use enclave_runner::EnclaveBuilder;
use sgx_isa::{PageType, Report, SecinfoFlags, Targetinfo};
use sgxs::loader::Load;
use sgxs::sgxs::{PageChunk, SecinfoTruncated, SgxsWrite};

pub fn report<L: Load>(targetinfo: &Targetinfo, enclave_loader: &mut L) -> Result<Report, Error> {
    unsafe {
        let mut report = Report::default();
        let mut report_enclave = include_bytes!("../enclave/report.sgxs").to_vec();
        let mut targetinfo: &[u8] = targetinfo.as_ref();
        let secinfo = SecinfoTruncated {
            flags: SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
        };
        report_enclave
            .write_page(
                (&mut targetinfo, [PageChunk::Included; 16]),
                0x3000,
                secinfo,
            )
            .unwrap();

        EnclaveBuilder::new_from_memory(&report_enclave)
            .build_library(enclave_loader)
            .context("failed to load report enclave")?
            .call(&mut report as *mut _ as _, 0, 0, 0, 0)
            .context("failed to call report enclave")?;
        Ok(report)
    }
}
