import logging
from .detectors import (
    DetectInvalid,
    DetectIntegerOverflow,
    DetectUninitializedStorage,
    DetectUninitializedMemory,
    DetectReentrancySimple,
    DetectReentrancyAdvanced,
    DetectUnusedRetVal,
    DetectSuicidal,
    DetectDelegatecall,
    DetectExternalCallAndLeak,
    DetectEnvInstruction,
    DetectRaceCondition,
    DetectManipulableBalance,
)
from ..utils.enums import DetectorClassification
from ..core.plugin import Profiler
from .manticore import ManticoreEVM
from .plugins import (
    FilterFunctions,
    LoopDepthLimiter,
    VerboseTrace,
    KeepOnlyIfStorageChanges,
    SkipRevertBasicBlocks,
)
from ..utils.nointerrupt import WithKeyboardInterruptAs
from ..utils import config

logger = logging.getLogger(__name__)

consts = config.get_group("cli")
consts.add("profile", default=False, description="Enable worker profiling mode")
consts.add(
    "explore_balance",
    default=False,
    description="Explore states in which only the balance was changed",
)

consts.add(
    "skip_reverts",
    default=False,
    description="Simply avoid exploring basic blocks that end in a REVERT",
)


def get_detectors_classes():
    return [
        DetectInvalid,
        DetectIntegerOverflow,
        DetectUninitializedStorage,
        DetectUninitializedMemory,
        DetectReentrancySimple,
        DetectReentrancyAdvanced,
        DetectUnusedRetVal,
        DetectSuicidal,
        DetectDelegatecall,
        DetectExternalCallAndLeak,
        DetectEnvInstruction,
        DetectManipulableBalance,
        # The RaceCondition detector has been disabled for now as it seems to collide with IntegerOverflow detector
        # DetectRaceCondition
    ]


def choose_detectors(args):
    all_detector_classes = get_detectors_classes()
    detectors = {d.ARGUMENT: d for d in all_detector_classes}
    arguments = list(detectors.keys())

    detectors_to_run = []

    if not args.exclude_all:
        exclude = []

        if args.detectors_to_exclude:
            exclude = args.detectors_to_exclude.split(",")
            for e in exclude:
                if e not in arguments:
                    raise Exception(
                        f"{e} is not a detector name, must be one of {arguments}. See also `--list-detectors`."
                    )

        for arg, detector_cls in detectors.items():
            if arg not in exclude:
                print(detector_cls)
                detectors_to_run.append(detector_cls)

    return detectors_to_run

def check_vulnerability(file_name):
    file1 = open(file_name, 'r')
    Lines = file1.readlines()
    count = 0
    # file1 = open("myfile.txt", "r+")
    # a = file1.read()
    # a = (list(map(int, a.split())))
    for line in Lines:
        count += 1
        #print("Line{}: {}".format(count, line.strip()))
        if ".send(" in line:
            # a[0]+=1
            logger.warning("Use Of Delegate Call. RECOMMENDATION : Change Send Call to Transfer CAll.")
            break
        if "block.timestamp" in line:
            # a[1]+=1
            logger.warning("Use Of Block.timestamp. RECOMMENDATION : Make sure block's timestamp is not used as source of entropy.")
            break
        if "tx.origin" in line:
            # a[2]+=1
            logger.warning("Use Of tx.origin. RECOMMENDATION : Make sure tx.origin is not used as source of Authentication.")
            break
        if "now" in line:
            logger.warning("Use Of now. RECOMMENDATION : Make sure now is not used as source of Authentication.")
            break
        if "block.blockhash" in line:
            logger.warning("Use Of block.blockhash. RECOMMENDATION : Make sure block.blockhash is not used as source of Authentication.")
            break
    # st = ""
        # for i in a:
    #     st += str(i)
    #     st += " "
    # file1.seek(0)
    # file1.write(st)
    file1.close()


def ethereum_main(args, logger):
    # print("WOekdsd : ",args.argv, os.getcwd())`
    m = ManticoreEVM(workspace_url=args.workspace)
    check_vulnerability(args.argv[0])
    if not args.thorough_mode:
        args.avoid_constant = True
        args.exclude_all = True
        args.only_alive_testcases = True
        consts_evm = config.get_group("evm")
        consts_evm.oog = "ignore"
        consts.skip_reverts = True

    with WithKeyboardInterruptAs(m.kill):
        if consts.skip_reverts:
            m.register_plugin(SkipRevertBasicBlocks())

        if consts.explore_balance:
            m.register_plugin(KeepOnlyIfStorageChanges())

        if args.verbose_trace:
            m.register_plugin(VerboseTrace())

        if args.limit_loops:
            m.register_plugin(LoopDepthLimiter())

        for detector in choose_detectors(args):
            m.register_detector(detector())

        if consts.profile:
            profiler = Profiler()
            m.register_plugin(profiler)

        if args.avoid_constant:
            # avoid all human level tx that has no effect on the storage
            filter_nohuman_constants = FilterFunctions(
                regexp=r".*", depth="human", mutability="constant", include=False
            )
            m.register_plugin(filter_nohuman_constants)

        if m.plugins:
            logger.info(f'Registered plugins: {", ".join(d.name for d in m.plugins.values())}')

        logger.info("Beginning analysis")

        with m.kill_timeout():
            m.multi_tx_analysis(
                args.argv[0],
                contract_name=args.contract,
                tx_limit=args.txlimit,
                tx_use_coverage=not args.txnocoverage,
                tx_send_ether=not args.txnoether,
                tx_account=args.txaccount,
                tx_preconstrain=args.txpreconstrain,
                compile_args=vars(args),  # FIXME
            )

        if not args.no_testcases:
            m.finalize(only_alive_states=args.only_alive_testcases)
        else:
            m.kill()

        for detector in list(m.detectors):
            m.unregister_detector(detector)

        for plugin in list(m.plugins):
            m.unregister_plugin(plugin)
