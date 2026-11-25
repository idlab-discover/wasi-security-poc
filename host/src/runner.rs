//! Instantiates a guest under a configured [`WasiCtxBuilder`] and runs it.
//!
//! WASI preview 2 components get the full `wasi:cli/command` world, including
//! `wasi:sockets`. Core modules (WASI preview 1) are supported too, but have
//! no sockets, so only `arguments`, `env` and `storage` apply to them.

use std::path::Path;

use anyhow::{Context, Result};
use wasmtime::component::{Component, ResourceTable};
use wasmtime::{Engine, Module, Store};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::bindings::sync::Command;
use wasmtime_wasi::{I32Exit, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

struct ComponentState {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl WasiView for ComponentState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

/// Components start with the `\0asm` magic followed by layer 1.
pub fn is_component(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[0..4] == *b"\0asm" && bytes[6..8] == [0x01, 0x00]
}

/// Run the guest to completion and return its exit code.
pub fn run(engine: &Engine, path: &Path, bytes: &[u8], mut builder: WasiCtxBuilder) -> Result<i32> {
    let outcome = if is_component(bytes) {
        run_component(engine, bytes, builder)
    } else {
        run_module(engine, bytes, builder.build_p1())
    };

    match outcome {
        Ok(code) => Ok(code),
        Err(err) => match err.downcast_ref::<I32Exit>() {
            Some(exit) => Ok(exit.0),
            None => Err(err).with_context(|| format!("failed to run '{}'", path.display())),
        },
    }
}

fn run_component(engine: &Engine, bytes: &[u8], mut builder: WasiCtxBuilder) -> Result<i32> {
    let component = Component::new(engine, bytes)?;

    let mut linker = wasmtime::component::Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;

    let state = ComponentState {
        ctx: builder.build(),
        table: ResourceTable::new(),
    };
    let mut store = Store::new(engine, state);
    let command = Command::instantiate(&mut store, &component, &linker)?;

    Ok(match command.wasi_cli_run().call_run(&mut store)? {
        Ok(()) => 0,
        Err(()) => 1,
    })
}

fn run_module(engine: &Engine, bytes: &[u8], ctx: WasiP1Ctx) -> Result<i32> {
    let module = Module::new(engine, bytes)?;

    let mut linker = wasmtime::Linker::new(engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx)?;

    let mut store = Store::new(engine, ctx);
    let instance = linker.instantiate(&mut store, &module)?;
    instance
        .get_typed_func::<(), ()>(&mut store, "_start")?
        .call(&mut store, ())?;
    Ok(0)
}
