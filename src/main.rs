#![feature(let_chains)]
#![feature(string_remove_matches)]

mod results;
mod util;

use lazy_static::lazy_static;
use regex::Regex;
use results::{Comparison, CrateResult, DiagnosticCode, RawTestResults, TestResult};
use tracing::{debug, error, trace};
use walkdir::WalkDir;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Duration;

use crate::results::{crate_to_path_fragment, SanitizationContext};

fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let file = File::open("results.json")?;
    let reader = BufReader::new(file);
    let raw_results: RawTestResults = serde_json::from_reader(reader)?;
    let mut regressed_crates = raw_results.crates;
    regressed_crates.retain(|c| {
        c.res == Comparison::Regressed
            // Previous run passed...
            && c.runs[0].as_ref().is_some_and(|r| r.res == TestResult::TestPass)
            // ... but now build failed due to `unit_bindings`
            && c.runs[1].as_ref().is_some_and(|r| {
                if let TestResult::BuildFail(results::FailureReason::CompilerError(e)) = &r.res
                    && e.contains(&DiagnosticCode { code: "unit_bindings".to_string() })
                {
                    true
                } else {
                    false
                }
            })
    });

    debug!("regressed_crates.len() = {}", regressed_crates.len());
    debug!("regressed_crates[0].runs = {:?}", regressed_crates[0].runs);

    let regressed_crate_log_paths = regressed_crates
        .into_iter()
        .map(crate_to_name_log_path)
        .collect::<BTreeMap<_, _>>();

    debug!(
        "regressed_crate_log_paths.len() = {}",
        regressed_crate_log_paths.len()
    );
    debug!(
        "regressed_crate_log_paths[0] = {:?}",
        regressed_crate_log_paths.iter().next().unwrap()
    );

    let mut remaining_crates: BTreeMap<String, Vec<String>> = BTreeMap::default();
    for (name, path) in regressed_crate_log_paths {
        trace!("analyzing {}", name);
        let mut relevant_lines = Vec::new();
        let log_file = File::open(path)?;
        let reader = BufReader::new(log_file);

        let mut iter = reader.lines();
        while let Some(line) = iter.next() {
            let line = line.unwrap();

            if line.contains("error: binding has unit type `()`") {
                // Take some context.
                let combined_rl = iter
                    .by_ref()
                    .take(9)
                    .map(|s| s.unwrap())
                    .collect::<Vec<_>>()
                    .join("\n");
                relevant_lines.push(combined_rl);
            }
        }

        if !relevant_lines.is_empty() {
            remaining_crates.insert(name, relevant_lines);
        }
    }

    println!(
        "total_error_messages: {}",
        remaining_crates.values().flatten().count()
    );

    let proc_macro_annotated_functions_names = vec![
        "Abhishekjena93.chat-app.084e4a325e8a0d95a8affa5a4d6ef1d2e3d73ee3",
        "AleardoKandiah.rust-app.a39ae916de97d3a933f6f7e9c33cdfeeb33ea9e5",
        "Al-khali.rust_chat_app.a9373c9e1cb04ee91004ef88a3a8d224e23ff3b3",
        "Anderson0xFF.TradeEngine_API.923bd444b3dbc4ebce4471f9c2d385478e6e6ffa",
        "ArtiomTr.boxer.a7f0f72dc45cb736ec8302a84985763fb35ddcba",
        "BawnX.rocket-first.308cd7c06f3fa147c3b9ce7f392f475978607ac9",
        "BroGamer4256.divamodarchive.4a283bcd1854b01597003a7b24b6a4eacd2923a2",
        "Dheatly23.godot-wasm.f913b071d12aa2b14d055191a38d8049ed662b93",
        "Eliasin.sysc4806project.7faf1acf5033fdfae43638c11a45f87d67cf20bd",
        "JesseAbram.rocket_testing_issue.ec4baac3bb96b6f04ab72f975dfdc6673b45b4bb",
        "KaratsubaLabs.onigiri-server.f65db5dc7ad73638fc8a74c348cdc83b5324e8e9",
        "Lunarequest.lunatree.40442a27853728cf861751af5b19f8173152332d",
        "Misterio77.SCC0541-Lab-BD-Projeto.06b4b27a80bf408fa9155f17c0df3918d58716dc",
        "NeoLight1010.spots-api.12f64a39d2cbc8d05c42bde7afcb01b85d39729c",
        "Nexlson.Mahjong-Backend.593b2430248b6dfa4d0e85323a92027dc786c462",
        "NolValue.atomic.c9d4e0183a28f9c62da939b9d28c2ed0963fd216",
        "Pigolitsyn.rust-server.4dbf049be83a7606710719c1735041938da9aa14",
        "PygmalionAI.collect_data.2f5ffc11b184ea119140a9537843ae535bf89fe0",
        "R0CKB0TT0M.plexhue.f2741e10853bb3070fcd02bc20c3d1b319b72a5c",
        "Rushmore75.pulse_remote.006b7c5b702994ae72956cad2cf00f995a387a35",
        "SerggioPizzella.beam.72d07a4450b21945f3e016c27bc0c2b3286fa1b2",
        "acmutd.jury.4ce478239ff56f60fa163f0a39d0d59907121ab4",
        "aiguy110.webhook2websocket.fbec5736936502dbbde8cdc6c2636695a73a7727",
        "cassaundra.uwupaste.112189a73504076aa479bec537bef43d8c8c8209",
        "chriamue.nft-login.d7b12cc14fc949a21af6cc33daf14f8987c6c9cd",
        "clonejo.clubstatusd.b5ab4e1919eced214db4cc1c4b0b5170f404676e",
        "cooscoos.RustBucket.67734afa6b3a9007101aa2aad0ffee5d3f4d3288",
        "cwhakes.cwh-basic.45f6cadc6902620eb3f46d98df186ac33cb5b8f1",
        "digitalillusion.remote_colonies.a14ec3ae3467317df46f2b97c88571db6059325b",
        "divinerapier.rust-examples.d45e78a2006170efefb841887e3d0bebf93d316d",
        "duaifzn.linebot.4ec52ed102f7a21c9adf2488313fd0d914c068de",
        "eframework-0.1.0",
        "fazekaszs.protonation-states-backend.8ff2ac3e2d6c53ae0fe208ae787489f6f2dbc60a",
        "gilengel.proc-server.4f92a1e972c26c0957a729f8be9140cceedbe37b",
        "hamidrezakp.kanvas.ed52c2b83d68483a15059b3ac8306c95db07933c",
        "hashed-io.bdk-services.6efcc7c952b74195ca985bb851421d13beb04ee3",
        "heyjul.BeSTS_API.fec01e52ab1675961b005bdc38fd0e82981cfabc",
        "id-contact.auth-test.c467d2863a9ca83d40787f239f6d17f0d32c8362",
        "jbfp.videocaster.3020e4d01fdd65883af91497411b7d7782c3b982",
        "jusvait.HelplyBackend.348ce0fe2eea681d9825360d487489a35d65f804",
        "kennycallado.PFC-server.4bac75490841cd5f4427724f52cd878780f33c06",
        "kpkym.koe-server.94eab9e57e81390e7ed8b74c6e04ee4229919c1e",
        "memochou1993.shortener-rust-api.6c214a1d41feda75d459a3cd6c801603ff45f430",
        "mkmik.ocipfs.476d377a42adbe6e33766629a3786858963c079d",
        "mtso.rabbithole.8e15470e5aa7ec22186a8814f5c27d67e0cda04d",
        "mvl-at.keg.0728900261db9e812917b6b2d57c4546f605fc9e",
        "oakpr.leaderboard.2860cd21a3cc653fba81e454a5bfcdd995cc42f4",
        "offdroid.swmn.8186d268da9b173247854e0ca003cd605b8e0b2d",
        "pettermk.kiddybank-api.febc38123e124349899bc11992eac863d6b56ee9",
        "pixelmonaskarion.messenger.e5aa63f292c8a0da66e490cc8f5c5608bed1d462",
        "pseudobabble.rocket-hello.eed7aedc225b17f28ae817b32c8a7005d91fa184",
        "quartz-server-0.3.0",
        "racetrack-0.0.2",
        "rishiad.rust_auth_server.753ba3e08068db0c980ad2d8cbce34b6832da253",
        "rivalq.Yew-Rocket-Todo.81f2bb22dc888954012c67e1c9294b951b355da2",
        "rob9315.ping-mc.b5891023d830d38b0de7ec3dc80ea7f9c318f6fe",
        "rocket-0.5.0-rc.3",
        "rocket_csrf-0.3.0",
        "rocket_modules-0.1.1",
        "roliveiravictor.demo-rust-learning.17c6d10d7e28e528fcf048650b8f62a9c8ab40a8",
        "rstropek.RustyRockets.27ff816d3612b162916fff85e6e61d160c64b128",
        "shaku_rocket-0.7.0-rc.1",
        "stakwork.sphinx-swarm.81ae1bbd0f793a164f78d66ee610f97b09b18b6b",
        "tandem_http_server-0.3.0",
        "tannaurus.Grandma.50497d763b3b56e55508cb165fd461f8519ed756",
        "the-auction-games.account-api.fe8149f89fb03519c3a10f87da42e3a2da3b37b0",
        "tweedegolf.tguard.61e6e3be8427d548e369c301d727698e794d07b8",
        "yaaawww.keyman.e5173b2cd233530dd4056bf6e2440ba765616650",
        "yoehwan.rust_todo_server.c0ed7ae2ce437faf506fcd619ff378e6e296731c",
        "yunusp.rental.a8f65bacff43a9e9d317d50070083cc52911bcf6",
        "zhangyi921.is-color-orange.b1d9a1947a4e46adde787cfd149e293c9eb31150",
    ];
    remaining_crates
        .retain(|name, _| !proc_macro_annotated_functions_names.contains(&name.as_str()));
    println!(
        "proc macro fn crates removed; remaining error messages: {}",
        remaining_crates.values().flatten().count()
    );

    let enumset_macros = vec!["BlankParenthesis.pxls-rs.d4ec12b7c6ffdaa457098c621a4522f245ecfc45"];
    remaining_crates.retain(|name, _| !enumset_macros.contains(&name.as_str()));
    println!(
        "enumset crates removed; remaining error messages: {}",
        remaining_crates.values().flatten().count()
    );

    debug!("remaining_crates = {}", remaining_crates.len());

    let special_macros = vec![
        "intercom-0.4.0",
        "lets_expect-0.5.1",
        "linyinfeng.rspg.b431fb00f34ff81ae5425e14494747df0c9e297b",
        "openrr-plugin-0.1.0",
        "phaneron-plugin-0.1.2",
        "pomelo-0.1.5",
        "smt2parser-0.6.1",
    ];
    remaining_crates.retain(|name, _| !special_macros.contains(&name.as_str()));
    println!(
        "special macros crates removed; remaining error messages: {}",
        remaining_crates.values().flatten().count()
    );

    let pyo3_macros = vec![
        "messense.lingua-py.3d97ee130f5b4954f89575be1fec90c730686be6",
        "messense.rjieba-py.63536c2f69282584431bfddd00d234ad27ae0e1c",
        "mozilla.pyo3-parsepatch.9bc6c2d5c2150818f79e300d301848a57e29b2c0",
        "pyo3-0.19.0",
    ];
    remaining_crates.retain(|name, _| !pyo3_macros.contains(&name.as_str()));
    println!(
        "py03 macros crates removed; remaining error messages: {}",
        remaining_crates.values().flatten().count()
    );

    let special_ui_macro_crate =
        vec!["prestonmlangford.mcts.20e683ca78398bffbc7ee2cccc3ec6040bd4d210"];
    remaining_crates.retain(|name, _| !special_ui_macro_crate.contains(&name.as_str()));
    println!(
        "special ui macro crates removed; remaining error messages: {}",
        remaining_crates.values().flatten().count()
    );

    let idk = vec!["musli-tests-0.0.3"];
    remaining_crates.retain(|name, _| !idk.contains(&name.as_str()));
    println!(
        "idk crates removed; remaining error messages: {}",
        remaining_crates.values().flatten().count()
    );

    lazy_static! {
        static ref LET_UNDERSCORE_REGEX: Regex = Regex::new(r"let _\s*=").unwrap();
    }

    let let_underscore_messages = remaining_crates
        .values()
        .flatten()
        .filter(|s| LET_UNDERSCORE_REGEX.is_match(s))
        .count();

    println!("let_underscore_messages: {}", let_underscore_messages);

    let mut remaining_crates_1 = BTreeMap::<String, Vec<String>>::new();
    for (name, mut error_messages) in remaining_crates {
        error_messages.retain(|m| !LET_UNDERSCORE_REGEX.is_match(m));
        if !error_messages.is_empty() {
            remaining_crates_1.insert(name, error_messages);
        }
    }

    debug!("remaining_crates_1.len() = {}", remaining_crates_1.len());

    lazy_static! {
        static ref LET_VAR_REGEX: Regex =
            Regex::new(r"let\s+(mut\s*)?[a-zA-Z][#a-zA-Z0-9_]*\s*=").unwrap();
    }

    let let_var_messages = remaining_crates_1
        .values()
        .flatten()
        .filter(|s| LET_VAR_REGEX.is_match(s))
        .count();

    println!("let_var_messages: {}", let_var_messages);

    let mut remaining_crates_2 = BTreeMap::<String, Vec<String>>::new();
    for (name, mut error_messages) in remaining_crates_1 {
        error_messages.retain(|m| !LET_VAR_REGEX.is_match(m));
        if !error_messages.is_empty() {
            remaining_crates_2.insert(name, error_messages);
        }
    }

    debug!("remaining_crates_2.len() = {}", remaining_crates_2.len());

    lazy_static! {
        static ref LET_UNDERSCORE_VAR_REGEX: Regex =
            Regex::new(r"let\s+(mut\s*)?_[#a-zA-Z0-9_]+\s*=").unwrap();
    }

    let let_underscore_var_messages = remaining_crates_2
        .values()
        .flatten()
        .filter(|s| LET_UNDERSCORE_VAR_REGEX.is_match(s))
        .count();

    println!(
        "let_underscore_var_messages: {}",
        let_underscore_var_messages
    );

    let mut remaining_crates_3 = BTreeMap::<String, Vec<String>>::new();
    for (name, mut error_messages) in remaining_crates_2 {
        error_messages.retain(|m| !LET_UNDERSCORE_VAR_REGEX.is_match(m));
        if !error_messages.is_empty() {
            remaining_crates_3.insert(name, error_messages);
        }
    }

    debug!("remaining_crates_3.len() = {}", remaining_crates_3.len());

    lazy_static! {
        static ref JSX_LIKE_MESSAGES: Regex = Regex::new(r"<\s*[a-zA-Z0-9\:_]+\s*/?>").unwrap();
    }

    let jsx_like_messages = remaining_crates_3
        .values()
        .flatten()
        .filter(|s| JSX_LIKE_MESSAGES.is_match(s))
        .count();

    println!("jsx_like_messages: {}", jsx_like_messages);

    let mut remaining_crates_4 = BTreeMap::<String, Vec<String>>::new();
    for (name, mut error_messages) in remaining_crates_3 {
        error_messages.retain(|m| !JSX_LIKE_MESSAGES.is_match(m));
        if !error_messages.is_empty() {
            remaining_crates_4.insert(name, error_messages);
        }
    }

    debug!("remaining_crates_4.len() = {}", remaining_crates_4.len());

    lazy_static! {
        static ref UNDERSCORE_ASSIGN: Regex = Regex::new(r"_\s*=").unwrap();
    }

    let underscore_assign_messages = remaining_crates_4
        .values()
        .flatten()
        .filter(|s| UNDERSCORE_ASSIGN.is_match(s))
        .count();

    println!("underscore_assign_messages: {}", underscore_assign_messages);

    let mut remaining_crates_5 = BTreeMap::<String, Vec<String>>::new();
    for (name, mut error_messages) in remaining_crates_4 {
        error_messages.retain(|m| !UNDERSCORE_ASSIGN.is_match(m));
        if !error_messages.is_empty() {
            remaining_crates_5.insert(name, error_messages);
        }
    }

    debug!("remaining_crates_5.len() = {}", remaining_crates_5.len());

    for (name, error_messages) in remaining_crates_5 {
        println!("CRATE: {}", name);
        for msg in error_messages {
            println!("ERROR MESSAGE:\n{}\n\n", msg);
        }
        println!("\n\n\n");
        std::thread::sleep(Duration::from_secs(5));
    }

    Ok(())
}

fn crate_to_name_log_path(cr: CrateResult) -> (String, PathBuf) {
    let mut search_path = PathBuf::new();
    search_path.push("regressed");
    search_path.push(cr.krate.id());
    debug!(?search_path);

    for entry in WalkDir::new(search_path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.file_name().to_string_lossy().contains("try#") {
            let mut log_path = PathBuf::new();
            log_path.push(entry.into_path());
            assert!(log_path.exists());
            return (cr.name, log_path);
        }
    }

    unreachable!()
}

fn setup_logging() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    let fmt_layer = fmt::layer()
        .compact()
        .with_level(true)
        .with_target(true)
        .without_time();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}
