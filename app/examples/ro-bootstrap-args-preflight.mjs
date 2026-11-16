import coreRuntime from "../src/core/runtime.mjs";

import { buildBootstrapArgs } from "./kaihen-bootstrap-args.mjs";

const {cloneObject: cloneObject, closeHandle: closeHandle, log: log, sdk_base: sdk_base} = coreRuntime;

const check = (ok, message) => {
    if (!ok) throw new Error("RO bootstrap input: " + message);
};

export async function run() {
    const fs = globalThis.civFsMemory;
    const state = fs?.status();
    const session = globalThis.fspSrv;
    const row = globalThis.civRoLoaderRow;
    const owned = globalThis.civRoOwned;
    const loader = globalThis.civRoLoaderRootCopy;
    const donor = globalThis.civRoDonor;
    const workers = globalThis.civRoWorkers?.list;
    const event = globalThis.civRoEvent;
    const map = globalThis.civRoBootstrapMap;
    check(state?.ready && state.candidateHandle >= 32768 && state.dataOffset === 16384 && state.dataEntryOffset === 144, "current FS endpoint does not expose retained candidate/channel");
    check(session?.handle && session.rootObj && row && owned?.waiters?.length === 7 && loader?.handle && donor?.handle && workers?.length === 7 && event?.notifierHandle && globalThis.civRoPmShell?.handle && globalThis.civRoPmMonitor?.handle && globalThis.civRoSmCopy?.handle && globalThis.civRoFsProcessCopy?.handle && globalThis.civRoLoaderServerCopy?.handle && globalThis.civRoRootPromotion?.root === state.fsRoot.object && map?.queryVerified && map.state === "mapped" && !globalThis.civRoBootstrapArgs, "RO frontend or retained handles are incomplete");
    check(loader.targetDomain === row.domain && loader.targetAddress === state.fsRoot.table + 8 * 48 && donor.metadata === globalThis.civRoDonorType?.metadata && donor.vptr === globalThis.civRoDonorType?.vptr, "Loader/donor identity differs");
    const promotedRootHandle = cloneObject(session.handle, session.rootObj);
    check(promotedRootHandle >= 32768, "could not clone promoted FS root");
    try {
        const bytes = buildBootstrapArgs({
            candidateHandle: state.candidateHandle,
            dataOffset: state.dataOffset,
            dataEntryOffset: state.dataEntryOffset,
            row: {
                ...row,
                vptr: state.fsRoot.rootVptr - 32120
            },
            waiters: owned.waiters,
            workers: workers.map(worker => worker.handle),
            event: event,
            loaderServerCopy: globalThis.civRoLoaderServerCopy.handle,
            root: state.fsRoot,
            loader: loader,
            rootId: 9,
            donor: donor,
            pmShell: globalThis.civRoPmShell.handle,
            pmMonitor: globalThis.civRoPmMonitor.handle,
            sdkBase: sdk_base,
            tryWaitAdapter: map.tryWaitAdapter,
            smHandle: globalThis.civRoSmCopy.handle,
            roHandle: globalThis.civRoFrontendService.handle,
            promotedRootHandle: promotedRootHandle,
            fsProcessHandle: globalThis.civRoFsProcessCopy.handle,
            notifierHandle: event.notifierHandle,
            loaderRootHandle: loader.handle
        });
        globalThis.civRoBootstrapArgs = {
            bytes: bytes,
            promotedRootHandle: promotedRootHandle,
            release() {
                if (globalThis.civRoBootstrapArgs !== this) return;
                closeHandle(promotedRootHandle);
                delete globalThis.civRoBootstrapArgs;
            }
        };
        await log("kaiHEN bootstrap input assembled: 432 bytes, " + "candidate=" + state.candidateHandle + " mapped=0x" + map.destination.toString(16) + " rootId=9; native thread not started");
    } catch (error) {
        closeHandle(promotedRootHandle);
        throw error;
    }
}
