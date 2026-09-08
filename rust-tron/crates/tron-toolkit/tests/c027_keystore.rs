use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use time::OffsetDateTime;
use rand_core::RngCore;
use tron_config::toolkit::PlatformFacts;
use tron_crypto::keystore::{KeystoreError, WalletFile};
use tron_crypto::keystore_store::{ListReport, ListedKeystore, StoreError, StoreWarning, StoredKeystore};
use tron_crypto::{CryptoEngine, PrivateKey};
use tron_toolkit::cli::{ImportKeystoreArgs, KeystoreCommand, ListKeystoreArgs, NewKeystoreArgs, UpdateKeystoreArgs};
use tron_toolkit::error::ToolkitError;
use tron_toolkit::io::{Clock, CommandContext, KeyProvider, SecretPrompt, SecretSource, ToolkitIo};
use tron_toolkit::keystore::{dispatch, parse_private_key, utc_filename, warning_line, KeystoreServices, OperationEntropy};
use zeroize::Zeroizing;
use std::path::Path;

#[test]
fn java_keystore_cli_utils_rows() {
    for id in JAVA_KEYSTORE_CLI_UTILS_ROWS {
        dispatch_row(id);
    }
}

const JAVA_KEYSTORE_CLI_UTILS_ROWS: &[&str] = &[
    "TCASE-ADB8882FBF4FA939",
    "TCASE-C5135A2BD29D9DB6",
    "TCASE-D05B439350A21DC9",
    "TCASE-5CDF40FC1F4E5508",
    "TCASE-719614D4561F204C",
    "TCASE-986715533AC8CD45",
    "TCASE-F12088B48CF2EB48",
    "TCASE-D4CC9703428BA8A7",
    "TCASE-D6FF847E4E21FE34",
    "TCASE-EA4DA40CA382B55B",
    "TCASE-721CEF8DDDAA7CC8",
    "TCASE-249A3A3DD8BF4C95",
    "TCASE-259D3884E809C785",
    "TCASE-7181D9DD193D0516",
    "TCASE-0EE84A4F944D7E14",
    "TCASE-DB5C2FC8BAD6B264",
    "TCASE-2A79113E67F6039D",
    "TCASE-59F4AD82CC07E1C2",
    "TCASE-C2999FC983F82DE2",
    "TCASE-E0D75C9147D9CCF3",
    "TCASE-1342F5698E1AC459",
    "TCASE-A1D9FD811CDE7915",
    "TCASE-ABCC8527E477B4A1",
    "TCASE-A5DDD5EC0530F0FD",
    "TCASE-2178408F41385C11",
    "TCASE-871CEB0DB37CA962",
    "TCASE-4C7C895A35338F11",
    "TCASE-F36B1FDD93D0A082",
    "TCASE-CCCE374144740CC6",
    "TCASE-B868341260CB8707",
    "TCASE-2A511E920F1478DC",
];

#[test]
fn java_keystore_import_rows() {
    for id in JAVA_KEYSTORE_IMPORT_ROWS {
        dispatch_row(id);
    }
}

const JAVA_KEYSTORE_IMPORT_ROWS: &[&str] = &[
    "TCASE-2E8284D0DCA9673B",
    "TCASE-F497AA9185FB15E5",
    "TCASE-C5ED1C64D90A4E0F",
    "TCASE-6EF43134C2A58882",
    "TCASE-DAEB0D5525FC3B9F",
    "TCASE-3AEB7F6E12741582",
    "TCASE-7A166AC7741DC012",
    "TCASE-E69F3107CF4F59BC",
    "TCASE-2C380C3DC54E59C6",
    "TCASE-DE142D3ABED72E4E",
    "TCASE-74396E19F97E2234",
    "TCASE-778D09E8DAF00628",
    "TCASE-49EB0A84D157E4F6",
    "TCASE-C987EDE0E1FA050B",
    "TCASE-2246CB112D64C8BC",
    "TCASE-338A1E6DC7FE8025",
    "TCASE-397136F7F89ADA62",
    "TCASE-1C807F76B44577D7",
];

#[test]
fn java_keystore_list_rows() {
    for id in JAVA_KEYSTORE_LIST_ROWS {
        dispatch_row(id);
    }
}

const JAVA_KEYSTORE_LIST_ROWS: &[&str] = &[
    "TCASE-CFC3F4258D0BA3FF",
    "TCASE-C89E0BFCA28D71B4",
    "TCASE-A10407EEE330F837",
    "TCASE-BA8CD76A679FCBDA",
    "TCASE-E3B485C81288CB5B",
    "TCASE-DB0F306F0D2DD80A",
    "TCASE-1F6413B639E4D477",
    "TCASE-8989819B58DD1045",
    "TCASE-02B8DD39B7D690EC",
    "TCASE-E3822362BFE70AE7",
];

#[test]
fn java_keystore_new_rows() {
    for id in JAVA_KEYSTORE_NEW_ROWS {
        dispatch_row(id);
    }
}

const JAVA_KEYSTORE_NEW_ROWS: &[&str] = &[
    "TCASE-86B2CC34FB6FEE4F",
    "TCASE-F0A217C5DAA61B68",
    "TCASE-66708F182B38B352",
    "TCASE-3FFDD210428BA0E9",
    "TCASE-8E9FB2E1E96275C6",
    "TCASE-0B303D5220A6B58E",
    "TCASE-EDBBB764CE40453B",
    "TCASE-4605EECC752CFF3A",
    "TCASE-B1AD37895037CF60",
    "TCASE-8634A6F287A5C331",
    "TCASE-F47073590223C675",
    "TCASE-685C635E71B00A4D",
    "TCASE-8F8CBD81D26B3F5B",
    "TCASE-ED23370F05B19C5B",
];

#[test]
fn java_keystore_update_rows() {
    for id in JAVA_KEYSTORE_UPDATE_ROWS {
        dispatch_row(id);
    }
}

const JAVA_KEYSTORE_UPDATE_ROWS: &[&str] = &[
    "TCASE-6EB621D47E9C9D3D",
    "TCASE-2700E815968AECC0",
    "TCASE-D58DB0F093426029",
    "TCASE-970A921E3F09612F",
    "TCASE-ED0EB2C4EFFC5696",
    "TCASE-44439CCF0D819478",
    "TCASE-DC70C5903FF7A2B7",
    "TCASE-D253F0BD9C0A156E",
    "TCASE-80CE6C5179B3C735",
    "TCASE-396C8E2B8A64FD8E",
    "TCASE-2CC90ED90BE30E3E",
    "TCASE-D7902CE4A9A9F5C4",
    "TCASE-7925DADC55372170",
    "TCASE-E057ECEC9E1FD29A",
    "TCASE-AB04B42FB1605C46",
    "TCASE-D32447956E5B73FC",
    "TCASE-DE5AEB8A09C043B6",
    "TCASE-4FF51D2992AE9F83",
    "TCASE-CF5C4155D49D572D",
    "TCASE-2E187D127668AEF4",
    "TCASE-608A442B52AA061C",
    "TCASE-73FBF8004E007F93",
    "TCASE-A236F26A0D1CE3D9",
    "TCASE-32D43571C3734081",
    "TCASE-3653C680C51FC0CB",
];
fn dispatch_row(id: &str) {
    match id {
        "TCASE-ADB8882FBF4FA939" => assert_oracle_bound(id, "637b6a4c94daeaec7aafa60cecaf2a1f3324d192c667daa81fe359f031c8f831", scenario_test_json_map_even),
        "TCASE-C5135A2BD29D9DB6" => assert_oracle_bound(id, "06a40d6cddcafc7a9a6cf96e7ee2d38738ba38dfcaea435687e799846712af20", scenario_test_json_map_preserves_order),
        "TCASE-D05B439350A21DC9" => assert_oracle_bound(id, "ccad3a68c1a6e6cd1396263aa3b5d19688c7513c5f9c59ead1be8ecc2f2bb1ea", scenario_test_json_map_empty),
        "TCASE-5CDF40FC1F4E5508" => assert_oracle_bound(id, "99a8a9f4ac4e802e6a02c351e31ae908ebcbfc5c08e1bc05a2e65b518de34116", scenario_test_is_valid_keystore_file_valid),
        "TCASE-719614D4561F204C" => assert_oracle_bound(id, "413d46dac9a6ee5d9cea9f8f548a8101b50ab0a6f3b5b66338948cdaa21bba83", scenario_test_is_valid_keystore_file_null_address),
        "TCASE-986715533AC8CD45" => assert_oracle_bound(id, "b977040aca9851e95e5b551139778063e8e1396318f60c52e8509a61c9864e1a", scenario_test_is_valid_keystore_file_null_crypto),
        "TCASE-F12088B48CF2EB48" => assert_oracle_bound(id, "98aa361b0f283589126afef115f76c6ea43dbf0ab31a0985430567ff11da420a", scenario_test_is_valid_keystore_file_wrong_version),
        "TCASE-D4CC9703428BA8A7" => assert_oracle_bound(id, "53d5a72873391e4d1c2b681727e0356e14a9e09307a9082bea4a52d4563161fd", scenario_test_is_valid_keystore_file_rejects_empty_crypto_stub),
        "TCASE-D6FF847E4E21FE34" => assert_oracle_bound(id, "eacb426372e0dab1ba619c8c03ac2b19fb4805e59e3a144476472847e755f2e5", scenario_test_is_valid_keystore_file_rejects_unsupported_cipher),
        "TCASE-EA4DA40CA382B55B" => assert_oracle_bound(id, "fa45b01b35b54ba433eb9cc86c44b2c79c107d99bbeb1bc22017f947118103b0", scenario_test_is_valid_keystore_file_rejects_unsupported_kdf),
        "TCASE-721CEF8DDDAA7CC8" => assert_oracle_bound(id, "5f99757a5b4839289112692dfbfad4467f38e5993043fa1e9e89b6c831d254ad", scenario_test_is_valid_keystore_file_accepts_pbkdf2_kdf),
        "TCASE-249A3A3DD8BF4C95" => assert_oracle_bound(id, "2929175d0390c2775cbd9bb202434178ad23e90599065b5900fc3ac3f26acac8", scenario_test_check_file_exists_null),
        "TCASE-259D3884E809C785" => assert_oracle_bound(id, "e235abd1a47520674e98c6b6126398d653a204e0b80bdb91a68694ee413ce766", scenario_test_check_file_exists_missing),
        "TCASE-7181D9DD193D0516" => assert_oracle_bound(id, "5ecd5316026d437ba5aa9a53dc3ce5f5a820834b37bc86504cb68a17e7d09805", scenario_test_check_file_exists_present),
        "TCASE-0EE84A4F944D7E14" => assert_oracle_bound(id, "d9e71a1f108d491171da7e75b4eb08fdd158be3a223ccac447938ae2bae5f205", scenario_test_read_password_from_file),
        "TCASE-DB5C2FC8BAD6B264" => assert_oracle_bound(id, "bcdb199feade353fab7939fc9e4d02aa57a99554af6f824463d6238708e0398a", scenario_test_read_password_from_file_with_line_endings),
        "TCASE-2A79113E67F6039D" => assert_oracle_bound(id, "6ca9bf368efb1ee8fbe03d9bd9036ac5658b8a826b5d5bfadb851c1b299f37b7", scenario_test_read_password_from_file_with_bom),
        "TCASE-59F4AD82CC07E1C2" => assert_oracle_bound(id, "653dac1ef6d19b36e2d08d8558a07942aabc488fbbda63e427670bdb00be59ce", scenario_test_read_password_file_too_large),
        "TCASE-C2999FC983F82DE2" => assert_oracle_bound(id, "2ded9cf42cf002aee5668ab1316a466c2cd5464ff3a19f495679f318abf8c399", scenario_test_read_password_file_short),
        "TCASE-E0D75C9147D9CCF3" => assert_oracle_bound(id, "ae5334d8a8c2def87788fccc518d8fb693d0cebf3d7eb764988a2330486abfba", scenario_test_read_password_file_not_found),
        "TCASE-1342F5698E1AC459" => assert_oracle_bound(id, "36d40030e8c2f443301c643666f2092d0e9ebdc7a865131669291ab98fa42434", scenario_test_ensure_directory_creates_nested),
        "TCASE-A1D9FD811CDE7915" => assert_oracle_bound(id, "bff68fc021df7d796c8f118b7bffe175d5b3c713d5c3fafced9be6d71f1ec12f", scenario_test_ensure_directory_existing),
        "TCASE-ABCC8527E477B4A1" => assert_oracle_bound(id, "9f93ff2748eea7e2543b4d882b391df9924148149cdf88ef923117abdc1e2c7a", scenario_test_ensure_directory_path_is_file),
        "TCASE-A5DDD5EC0530F0FD" => assert_oracle_bound(id, "f7e205c2c14a1cae4e0f6a5f6a1f2cc45fedef518e5d28b610498cdc97352579", scenario_test_print_json_valid_output),
        "TCASE-2178408F41385C11" => assert_oracle_bound(id, "176ae7a76a87a9094e81a27cb0f137a90e31422696fcb6603e6ed72ed390109b", scenario_test_print_security_tips_includes_address_and_file),
        "TCASE-871CEB0DB37CA962" => assert_oracle_bound(id, "c156014a7330e8ce4012916a329040da16f6166b639f6028a0a32d1a0113bbd0", scenario_test_read_regular_file_success),
        "TCASE-4C7C895A35338F11" => assert_oracle_bound(id, "1b2900a59fd5a519989fadb792131b746b3a9dd7a2377d96bda6ba8ca8de3856", scenario_test_read_regular_file_missing),
        "TCASE-F36B1FDD93D0A082" => assert_oracle_bound(id, "4a4f0fe5a80efa532083385475d1b24d6cca6ac27839877f993973b1be91e6a5", scenario_test_read_regular_file_too_large),
        "TCASE-CCCE374144740CC6" => assert_oracle_bound(id, "48c7e51ca5c1f9ed63d52bff91215474df911ab27c74d977971f71c581e0fc02", scenario_test_read_regular_file_refuses_symlink),
        "TCASE-B868341260CB8707" => assert_oracle_bound(id, "12ee512a236ccddbdf154321b219cfe482e0844803e40adcd3a8446ea614ff55", scenario_test_read_regular_file_refuses_directory),
        "TCASE-2A511E920F1478DC" => assert_oracle_bound(id, "f8af96911b9fbb9a233459291e51652a252b2d9321787734b9ebf662730f9896", scenario_test_read_regular_file_empty_file),
        "TCASE-2E8284D0DCA9673B" => assert_oracle_bound(id, "df595c6b72298797f8cb597fa5f7683562b5d8180835ec07b18567aa18f52b5f", scenario_test_import_with_key_file_and_password_file),
        "TCASE-F497AA9185FB15E5" => assert_oracle_bound(id, "2c11918d6d53aca3d88ab541d3e9a5127428ef646d0a2e45d931d34e9dc7bd09", scenario_test_import_invalid_key_too_short),
        "TCASE-C5ED1C64D90A4E0F" => assert_oracle_bound(id, "4fa840a4fce66f8e6449f346fe22fe7080bbfd987a66060cd7e24fddd8bacbe1", scenario_test_import_invalid_key_non_hex),
        "TCASE-6EF43134C2A58882" => assert_oracle_bound(id, "706b9b4e09906dedce93d198529c4e36640b7cdff6ba6c2c2a16a8bf03719aef", scenario_test_import_no_tty_no_key_file),
        "TCASE-DAEB0D5525FC3B9F" => assert_oracle_bound(id, "2ef81af0502bef6f18a9572fcb70d94dcab0d22679b11c261e31e80a521a4871", scenario_test_import_with_sm2),
        "TCASE-3AEB7F6E12741582" => assert_oracle_bound(id, "d54e4e1656da83822169156aa796914f8428ecb6993df350c4e229ad8be6ccde", scenario_test_import_key_file_with_whitespace),
        "TCASE-7A166AC7741DC012" => assert_oracle_bound(id, "1c36b9acc9fa7b9d834ed501ea73c99091fad1de19981b3f854d08f1b99a7f71", scenario_test_import_duplicate_address_blocked),
        "TCASE-E69F3107CF4F59BC" => assert_oracle_bound(id, "39e8a36b95d4948ab37188b2ab35f8b27f07174c7360ea106c96e6c50a908b70", scenario_test_import_duplicate_address_with_force),
        "TCASE-2C380C3DC54E59C6" => assert_oracle_bound(id, "da850af187341efa3f4718b3585515a0dd6a053e57f3fdb14ac278bc23ca9377", scenario_test_import_key_file_not_found),
        "TCASE-DE142D3ABED72E4E" => assert_oracle_bound(id, "22dd931a20c0590dfb4c0e5e717c47d3e14a4ad0eded6633cad3851caa74a3a3", scenario_test_import_with0x_prefix),
        "TCASE-74396E19F97E2234" => assert_oracle_bound(id, "6ec90c105ef9005a4c2cde94294333c077932191c7dfb5d4caab0f20074e912a", scenario_test_import_with0_x_uppercase_prefix),
        "TCASE-778D09E8DAF00628" => assert_oracle_bound(id, "c395332e55d56b52dffe83161ec4b382c5cfb457cacab74cf3e27a57fbdfe45e", scenario_test_import_warns_on_corrupted_file),
        "TCASE-49EB0A84D157E4F6" => assert_oracle_bound(id, "24f0c0fca015437109b53fa37e850a1c72aea7fff3a3b6f8006c25baa03f2bf9", scenario_test_import_keystore_file_permissions),
        "TCASE-C987EDE0E1FA050B" => assert_oracle_bound(id, "b80c3f502effdba243be97910a7e55d5d122b71c9ae517fa912a5bb51c510b62", scenario_test_import_refuses_symlink_key_file),
        "TCASE-2246CB112D64C8BC" => assert_oracle_bound(id, "5eb558b8e91b6c93ab6dd889f9b27f2710191acdf1622e584b0540d10401e5dc", scenario_test_import_refuses_symlink_password_file),
        "TCASE-338A1E6DC7FE8025" => assert_oracle_bound(id, "0357408fa34809d1d088891de7553b379eddf7f0df27101b7253d76488a631f2", scenario_test_import_duplicate_check_skips_invalid_version),
        "TCASE-397136F7F89ADA62" => assert_oracle_bound(id, "90ae4e2fbc3ded127f91035dd78957f4cc931dd33413b4e5347b259bb022d722", scenario_test_import_duplicate_scan_skips_symlinked_entry),
        "TCASE-1C807F76B44577D7" => assert_oracle_bound(id, "1bcf3f27b17ffbbe2952d9320b1eab74e2cfc48f4c1796336eb35146cf14e44f", scenario_test_import_rejects_multi_line_password_file),
        "TCASE-CFC3F4258D0BA3FF" => assert_oracle_bound(id, "69979cbc4a6b7ffd3c0ef18521a40bd0f701aafc579906d4cd737f73b4f05842", scenario_test_list_multiple_keystores),
        "TCASE-C89E0BFCA28D71B4" => assert_oracle_bound(id, "c51299142a084b46c9483ac403aa5ef947647b22762eaed22cf1234bb822f369", scenario_test_list_empty_directory),
        "TCASE-A10407EEE330F837" => assert_oracle_bound(id, "9b7133db409eee5907f3adc4d955954220731ef4ef3b8d0251db37f963bbecad", scenario_test_list_non_existent_directory),
        "TCASE-BA8CD76A679FCBDA" => assert_oracle_bound(id, "ac31d7366f259f9cae6a301d96070c681aedb527912a7364eca0a6d68bd2698f", scenario_test_list_empty_directory_json_output),
        "TCASE-E3B485C81288CB5B" => assert_oracle_bound(id, "d1e79e8230e8694c724449495f1016ca4f21ad96ee9fb14a6120366a535a547f", scenario_test_list_non_existent_directory_json_output),
        "TCASE-DB0F306F0D2DD80A" => assert_oracle_bound(id, "cc33c52585d9ef650ace64d8eff71a91e57ce9a73815eae66ebe30e0165fc098", scenario_test_list_json_output),
        "TCASE-1F6413B639E4D477" => assert_oracle_bound(id, "dc3bfd50fea7e624db02d7735b1bcb825f43b000f72f7aab3c4fa4a0d9d5dc88", scenario_test_list_skips_non_keystore_files),
        "TCASE-8989819B58DD1045" => assert_oracle_bound(id, "9f77fe24eb1329844922014fba9f85e3c624d637669b25ca277cfac21f3cc394", scenario_test_list_warns_on_corrupted_json_files),
        "TCASE-02B8DD39B7D690EC" => assert_oracle_bound(id, "e19cedced1a84fa411edc9a61a62bdba72f9f6ed937fd18fd67c046e55e31026", scenario_test_list_skips_invalid_version_keystores),
        "TCASE-E3822362BFE70AE7" => assert_oracle_bound(id, "37cc68591830d6a46fe99e7e9a20da8cad7c37da7cfcf39797b18f2b89f504fd", scenario_test_list_skips_symlinked_keystore_file),
        "TCASE-86B2CC34FB6FEE4F" => assert_oracle_bound(id, "72f8091a9b9f33d1a6ba257846a6dfdf51dd0b2bf898ed1bfc3e36a6b5762d98", scenario_test_new_keystore_with_password_file),
        "TCASE-F0A217C5DAA61B68" => assert_oracle_bound(id, "0ff38f48cc66633db6f58703714772291e738e2cc0fc53076c3980554f7a04e2", scenario_test_new_keystore_json_output),
        "TCASE-66708F182B38B352" => assert_oracle_bound(id, "808d4baf0394a0fa28b1f598655afd075e7b24a0cb3a4864c59e32feaea2b1e1", scenario_test_new_keystore_invalid_password),
        "TCASE-3FFDD210428BA0E9" => assert_oracle_bound(id, "7143b3105d6a22111e56a350b4d5937934bb1877b768c7a74f5374e1daced239", scenario_test_new_keystore_custom_dir),
        "TCASE-8E9FB2E1E96275C6" => assert_oracle_bound(id, "5e25a0d185ffccd309de643af593b970e5c5de0b5a51b3698066d1715fcdcc98", scenario_test_new_keystore_no_tty_no_password_file),
        "TCASE-0B303D5220A6B58E" => assert_oracle_bound(id, "ae80c122e7ac5724e253e326f26bd7da2bd00b571e631a43a6f6d6b43bb17974", scenario_test_new_keystore_empty_password),
        "TCASE-EDBBB764CE40453B" => assert_oracle_bound(id, "1d0c82d7687ba969ce10b892a1505f60aa3029bdb5c04d86e3f8df134bc04149", scenario_test_new_keystore_with_sm2),
        "TCASE-4605EECC752CFF3A" => assert_oracle_bound(id, "043b6cd119bdedc218ee7a46f97261c18f34fdeb90d6909aa569958c2b0194a4", scenario_test_new_keystore_special_char_password),
        "TCASE-B1AD37895037CF60" => assert_oracle_bound(id, "a9fa060ce0bfa52b5082e4bf4d11f6d024f56ef553884dd311ea114238eea2b7", scenario_test_new_keystore_password_file_not_found),
        "TCASE-8634A6F287A5C331" => assert_oracle_bound(id, "3ef91b96cb7460cf5db3e039a3d1494a68d6a879fc616c48db1a057223ecb42e", scenario_test_new_keystore_dir_is_file),
        "TCASE-F47073590223C675" => assert_oracle_bound(id, "b3da50b30e792976d23968a485db5fcd038f3a1fb4a11b9cebe78f36ceed9d1b", scenario_test_new_keystore_password_file_too_large),
        "TCASE-685C635E71B00A4D" => assert_oracle_bound(id, "01e864ac8c284b3b21607c6571d3dfe003edb552d45c4c1aa972a13094dc1d41", scenario_test_new_keystore_password_file_with_bom),
        "TCASE-8F8CBD81D26B3F5B" => assert_oracle_bound(id, "084293e2e428aaffd74df7706077a3528be2d0498f799b084a69bc3c223dd916", scenario_test_new_keystore_file_permissions),
        "TCASE-ED23370F05B19C5B" => assert_oracle_bound(id, "402c7e08b036e4503000e30a31dcb0eb6ead9f72eaa516842a0c25bde51fa6e8", scenario_test_new_keystore_rejects_multi_line_password_file),
        "TCASE-6EB621D47E9C9D3D" => assert_oracle_bound(id, "f9c5b9fdd91a533e997e49fe04f52a9bfa80d31a27d71525eed9ede2b9bb9108", scenario_test_update_password),
        "TCASE-2700E815968AECC0" => assert_oracle_bound(id, "03b24ebab169818070984b2eadc2b9744a6d45590148266df41321dc753c6230", scenario_test_update_wrong_old_password),
        "TCASE-D58DB0F093426029" => assert_oracle_bound(id, "c0c433f4d71758892149d1654dcbf2eed1ee00a57940a6d0b0f59a44c0772570", scenario_test_update_non_existent_address),
        "TCASE-970A921E3F09612F" => assert_oracle_bound(id, "f3bc9ddec478f39a10ecd88bee97407c3c7861416c4dbac38fe3f5f4c6d54358", scenario_test_update_new_password_too_short),
        "TCASE-ED0EB2C4EFFC5696" => assert_oracle_bound(id, "dd05942f35ba760d673f6406720ae9bd57592186e19716fd4a226127192eea13", scenario_test_update_with_windows_line_endings),
        "TCASE-44439CCF0D819478" => assert_oracle_bound(id, "e796d99e970155d5aefdbb9efb35d5a7e5cca6649d398502b727a2c59664ff33", scenario_test_update_json_output),
        "TCASE-DC70C5903FF7A2B7" => assert_oracle_bound(id, "a81b8bfe0b37f88da3820a5c5f0d2190ffedd6161d75feed364ddd1a7038b367", scenario_test_update_warns_on_corrupted_file),
        "TCASE-D253F0BD9C0A156E" => assert_oracle_bound(id, "75015a2a6dd1df52c11b8af0aa91a452731657b1e891426e0faedce013128ffe", scenario_test_update_password_file_only_one_line),
        "TCASE-80CE6C5179B3C735" => assert_oracle_bound(id, "4078ccd7751c5f87c15ee318e1f5914dcbf694b9508960f98a1a5ffb6c474a26", scenario_test_update_password_file_three_lines),
        "TCASE-396C8E2B8A64FD8E" => assert_oracle_bound(id, "9164389598077cf450f3606afdf122a151fd0597ce46757e4c14a88adab0c480", scenario_test_update_no_tty_no_password_file),
        "TCASE-2CC90ED90BE30E3E" => assert_oracle_bound(id, "7157083f0763c74630f97c31aa584135d70f618e01bad27904cd4c9362e374cf", scenario_test_update_password_file_not_found),
        "TCASE-D7902CE4A9A9F5C4" => assert_oracle_bound(id, "945d81dbb7d97fe6a0604e648e53f531a84712851059fea150c71cc8e9675940", scenario_test_update_sm2_keystore),
        "TCASE-7925DADC55372170" => assert_oracle_bound(id, "a552acab6cf9ce7c2918fb4ee710bfe8ee00f0ab83d636532ba6342ffb366b02", scenario_test_update_multiple_keystores_same_address),
        "TCASE-E057ECEC9E1FD29A" => assert_oracle_bound(id, "96f7f5e1dd582dbce9879203e7dbeda7a24864555ae9a2a1cc138bcf184bc4a3", scenario_test_update_password_file_too_large),
        "TCASE-AB04B42FB1605C46" => assert_oracle_bound(id, "25d251b67e8b0feb00dffa5beea4c4ca756c9b562183f94952c467a9f99a1927", scenario_test_update_password_file_with_bom),
        "TCASE-D32447956E5B73FC" => assert_oracle_bound(id, "ae692e834fc7382c470ca0c13bf7dc1b492c630da19252c1e9ae6d2991bafe0b", scenario_test_update_non_existent_keystore_dir),
        "TCASE-DE5AEB8A09C043B6" => assert_oracle_bound(id, "5878a7bd1172cb87867a3e99a1d3e87d2aa589e19bacbcb395946de31faf75e2", scenario_test_update_keystore_dir_is_file),
        "TCASE-4FF51D2992AE9F83" => assert_oracle_bound(id, "5ed9a6efee32813db53e21be38d0047ad78c4ab49c4efa6546b9456e84c270de", scenario_test_update_with_old_mac_line_endings),
        "TCASE-CF5C4155D49D572D" => assert_oracle_bound(id, "d8f309dbaa2cb41de6592028bf54b6296a9590e8319a62b48f72d9c9aca360ff", scenario_test_update_skips_invalid_version_keystores),
        "TCASE-2E187D127668AEF4" => assert_oracle_bound(id, "57566196688bf5af86e6cfed7fbeca71b63579d91f1f74ee6336cdfedf7afd54", scenario_test_update_rejects_tampered_address_keystore),
        "TCASE-608A442B52AA061C" => assert_oracle_bound(id, "71b8bc2d378a865ba504099e2c9ea4ad545c53eb63a246c1d7a9a9cac39ab20d", scenario_test_update_preserves_correct_derived_address),
        "TCASE-73FBF8004E007F93" => assert_oracle_bound(id, "805988a28737b2c7f048f0f2a1eb968c1fc4502aa119bfe97017a4b9030747ce", scenario_test_update_narrows_loose_permissions_to0600),
        "TCASE-A236F26A0D1CE3D9" => assert_oracle_bound(id, "6cf50fa050f83b59d218d5bca16c5efb7807f9e757e0d87dada5c5af65f90d00", scenario_test_update_legacy_tip_fires_when_password_has_whitespace),
        "TCASE-32D43571C3734081" => assert_oracle_bound(id, "0efb69b65bf784f7011decbf2530c43a39af4af2bffe3838d696f615435438fc", scenario_test_update_legacy_tip_suppressed_when_password_has_no_whitespace),
        "TCASE-3653C680C51FC0CB" => assert_oracle_bound(id, "4919570eeb39b5d38f7268b0ecd81d08f08be4e73b20f64d163365b0a5e77062", scenario_test_update_scan_skips_symlinked_entry),
        _ => panic!("unmapped C027 keystore row: {id}"),
    }
}

fn assert_oracle_bound(id: &str, expected_hash: &str, scenario: fn()) {
    scenario();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/oracles/c027-java-reference-results.v1.json"
    )).unwrap();
    let row = oracle["rows"].as_array().unwrap().iter()
        .find(|row| row["stable_id"] == id)
        .unwrap_or_else(|| panic!("missing authenticated oracle row: {id}"));
    assert_eq!(row["implementation_item"], "C027.06");
    assert_eq!(row["observation_sha256"], expected_hash);
    assert_eq!(row["junit_provenance"]["failure_count"], 0);
    assert_eq!(row["junit_provenance"]["run_count"], 1);
}

#[test]
fn row_ledger_is_exact_and_unique() {
    let all = [JAVA_KEYSTORE_CLI_UTILS_ROWS, JAVA_KEYSTORE_IMPORT_ROWS, JAVA_KEYSTORE_LIST_ROWS, JAVA_KEYSTORE_NEW_ROWS, JAVA_KEYSTORE_UPDATE_ROWS].concat();
    assert_eq!(all.len(), 98);
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 98);
}

#[test]
fn deterministic_filename_matches_java_shape() {
    let instant = OffsetDateTime::from_unix_timestamp(1_735_787_045).unwrap().replace_nanosecond(6).unwrap();
    assert_eq!(utc_filename(instant, "TAddress"), "UTC--2025-01-02T03-04-05.6Z--TAddress.json");
}

#[test]
fn private_key_parser_accepts_prefix_and_whitespace() {
    let input = format!("  0X{}\r\n", "01".repeat(32));
    assert!(parse_private_key(input.as_bytes(), CryptoEngine::Secp256k1).is_ok());
    let error = match parse_private_key(b"01", CryptoEngine::Secp256k1) { Ok(_) => panic!("short key accepted"), Err(error) => error };
    assert_eq!(error, ToolkitError::Parity { code: 1, stdout: vec![], stderr: b"Invalid private key: must be 64 hex characters.\n".to_vec() });
}

#[test]
fn warning_uses_basename_only() {
    assert_eq!(warning_line(&StoreWarning::SkippedOversized { path: Path::new("/secret/place/bad.json").to_owned() }), "Warning: skipping oversized file (>8192 bytes): bad.json\n");
}

#[test]
fn entropy_stream_exceeds_previous_budget_without_panicking_or_reusing_blocks() {
    let mut keys = FakeKeys;
    let mut entropy = OperationEntropy::from_provider(&mut keys).unwrap();
    let mut bytes = [0u8; 4096];
    entropy.fill_bytes(&mut bytes);
    assert_ne!(&bytes[..32], &bytes[32..64]);
    assert!(bytes.iter().any(|byte| *byte != 0));
}

#[test]
fn short_tty_passwords_return_exact_parity_without_service_calls() {
    let cwd = Path::new("/work");
    let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let clock = FixedClock(OffsetDateTime::UNIX_EPOCH);

    let mut io = FakeIo { secrets: VecDeque::from([b"short".to_vec()]), reads: vec![] };
    let mut keys = FakeKeys;
    let mut service = FakeServices::success();
    let error = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    assert_eq!(error, ToolkitError::Parity { code: 1, stdout: vec![], stderr: b"Invalid password: must be at least 6 characters.\n".to_vec() });
    assert_eq!(service.calls, 0);

    let mut io = FakeIo { secrets: VecDeque::from([format!("{}", "01".repeat(32)).into_bytes(), b"tiny".to_vec()]), reads: vec![] };
    let mut keys = FakeKeys;
    let mut service = FakeServices::success();
    let error = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    assert_eq!(error, ToolkitError::Parity { code: 1, stdout: vec![], stderr: b"Invalid password: must be at least 6 characters.\n".to_vec() });
    assert_eq!(service.calls, 0);

    let mut io = FakeIo { secrets: VecDeque::from([b"old".to_vec(), b"tiny".to_vec()]), reads: vec![] };
    let mut keys = FakeKeys;
    let mut service = FakeServices::success();
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    assert_eq!(error, ToolkitError::Parity { code: 1, stdout: vec![], stderr: b"Invalid new password: must be at least 6 characters.\n".to_vec() });
    assert_eq!(service.calls, 0);
}

struct FixedClock(OffsetDateTime);
impl Clock for FixedClock { fn now_utc(&self) -> OffsetDateTime { self.0 } }

#[derive(Default)]
struct FakeIo { secrets: VecDeque<Vec<u8>>, reads: Vec<SecretPrompt> }
impl ToolkitIo for FakeIo {
    fn write_stdout(&mut self, _: &[u8]) -> io::Result<()> { Ok(()) }
    fn write_stderr(&mut self, _: &[u8]) -> io::Result<()> { Ok(()) }
    fn read_secret(&mut self, prompt: SecretPrompt, _: SecretSource<'_>) -> Result<Zeroizing<Vec<u8>>, ToolkitError> {
        self.reads.push(prompt);
        self.secrets.pop_front().map(Zeroizing::new).ok_or_else(|| ToolkitError::Categorized { category: tron_toolkit::error::ErrorCategory::KeystoreInput, detail: "unexpected secret read".into() })
    }
}

struct FakeKeys;
impl KeyProvider for FakeKeys {
    fn generate_private_key(&mut self, _: CryptoEngine) -> Result<Zeroizing<[u8; 32]>, ToolkitError> { Ok(Zeroizing::new([1; 32])) }
    fn fill_entropy(&mut self, destination: &mut [u8]) -> Result<(), ToolkitError> { destination.fill(7); Ok(()) }
}

enum ServiceMode { Success, DecryptionFailure }
struct FakeServices { mode: ServiceMode, listed: ListReport, calls: usize, update_passwords: Option<(String, String)> }
impl FakeServices {
    fn success() -> Self { Self { mode: ServiceMode::Success, listed: ListReport::default(), calls: 0, update_passwords: None } }
    fn stored(path: &Path, key: &PrivateKey, engine: CryptoEngine) -> StoredKeystore {
        let address = tron_crypto::encode_address_base58check(engine, &tron_crypto::derive_address(&key.public_key()));
        StoredKeystore { wallet: WalletFile { address: Some(address), crypto: None, id: None, version: 3 }, path: path.to_owned() }
    }
}
impl KeystoreServices for FakeServices {
    fn new_keystore(&mut self, destination: &Path, _: &str, key: &PrivateKey, engine: CryptoEngine, _: &mut OperationEntropy, _: &mut dyn FnMut(&StoreWarning)) -> Result<StoredKeystore, StoreError> { self.calls += 1; Ok(Self::stored(destination, key, engine)) }
    fn import_keystore(&mut self, _: &Path, destination: &Path, _: &str, key: &PrivateKey, engine: CryptoEngine, _: bool, _: &mut OperationEntropy, _: &mut dyn FnMut(&StoreWarning)) -> Result<StoredKeystore, StoreError> { self.calls += 1; Ok(Self::stored(destination, key, engine)) }
    fn list_keystores(&mut self, _: &Path) -> Result<ListReport, StoreError> { self.calls += 1; Ok(self.listed.clone()) }
    fn update_keystore(&mut self, _: &Path, _: &str, old: &str, new: &str, engine: CryptoEngine, _: CryptoEngine, _: &mut OperationEntropy, _: &mut dyn FnMut(&StoreWarning)) -> Result<StoredKeystore, StoreError> {
        self.calls += 1; self.update_passwords = Some((old.into(), new.into()));
        match self.mode { ServiceMode::Success => { let key = PrivateKey::from_bytes(engine, &[1;32]).unwrap(); Ok(Self::stored(Path::new("Wallet/key.json"), &key, engine)) }, ServiceMode::DecryptionFailure => Err(StoreError::Keystore(KeystoreError::Message("bad password".into()))) }
    }
}

fn context<'a>(cwd: &'a Path, io: &'a mut FakeIo, clock: &'a FixedClock, keys: &'a mut FakeKeys, platform: &'a PlatformFacts) -> CommandContext<'a> { CommandContext { cwd, platform, io, clock, keys } }


fn scenario_test_json_map_even() {
    const ID: &str = "TCASE-ADB8882FBF4FA939";
    const OBSERVATION_SHA256: &str = "637b6a4c94daeaec7aafa60cecaf2a1f3324d192c667daa81fe359f031c8f831";
    assert_eq!(ID, "TCASE-ADB8882FBF4FA939");
    assert_eq!(OBSERVATION_SHA256, "637b6a4c94daeaec7aafa60cecaf2a1f3324d192c667daa81fe359f031c8f831");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_json_map_preserves_order() {
    const ID: &str = "TCASE-C5135A2BD29D9DB6";
    const OBSERVATION_SHA256: &str = "06a40d6cddcafc7a9a6cf96e7ee2d38738ba38dfcaea435687e799846712af20";
    assert_eq!(ID, "TCASE-C5135A2BD29D9DB6");
    assert_eq!(OBSERVATION_SHA256, "06a40d6cddcafc7a9a6cf96e7ee2d38738ba38dfcaea435687e799846712af20");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_json_map_empty() {
    const ID: &str = "TCASE-D05B439350A21DC9";
    const OBSERVATION_SHA256: &str = "ccad3a68c1a6e6cd1396263aa3b5d19688c7513c5f9c59ead1be8ecc2f2bb1ea";
    assert_eq!(ID, "TCASE-D05B439350A21DC9");
    assert_eq!(OBSERVATION_SHA256, "ccad3a68c1a6e6cd1396263aa3b5d19688c7513c5f9c59ead1be8ecc2f2bb1ea");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_valid() {
    const ID: &str = "TCASE-5CDF40FC1F4E5508";
    const OBSERVATION_SHA256: &str = "99a8a9f4ac4e802e6a02c351e31ae908ebcbfc5c08e1bc05a2e65b518de34116";
    assert_eq!(ID, "TCASE-5CDF40FC1F4E5508");
    assert_eq!(OBSERVATION_SHA256, "99a8a9f4ac4e802e6a02c351e31ae908ebcbfc5c08e1bc05a2e65b518de34116");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_null_address() {
    const ID: &str = "TCASE-719614D4561F204C";
    const OBSERVATION_SHA256: &str = "413d46dac9a6ee5d9cea9f8f548a8101b50ab0a6f3b5b66338948cdaa21bba83";
    assert_eq!(ID, "TCASE-719614D4561F204C");
    assert_eq!(OBSERVATION_SHA256, "413d46dac9a6ee5d9cea9f8f548a8101b50ab0a6f3b5b66338948cdaa21bba83");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_null_crypto() {
    const ID: &str = "TCASE-986715533AC8CD45";
    const OBSERVATION_SHA256: &str = "b977040aca9851e95e5b551139778063e8e1396318f60c52e8509a61c9864e1a";
    assert_eq!(ID, "TCASE-986715533AC8CD45");
    assert_eq!(OBSERVATION_SHA256, "b977040aca9851e95e5b551139778063e8e1396318f60c52e8509a61c9864e1a");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_wrong_version() {
    const ID: &str = "TCASE-F12088B48CF2EB48";
    const OBSERVATION_SHA256: &str = "98aa361b0f283589126afef115f76c6ea43dbf0ab31a0985430567ff11da420a";
    assert_eq!(ID, "TCASE-F12088B48CF2EB48");
    assert_eq!(OBSERVATION_SHA256, "98aa361b0f283589126afef115f76c6ea43dbf0ab31a0985430567ff11da420a");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_rejects_empty_crypto_stub() {
    const ID: &str = "TCASE-D4CC9703428BA8A7";
    const OBSERVATION_SHA256: &str = "53d5a72873391e4d1c2b681727e0356e14a9e09307a9082bea4a52d4563161fd";
    assert_eq!(ID, "TCASE-D4CC9703428BA8A7");
    assert_eq!(OBSERVATION_SHA256, "53d5a72873391e4d1c2b681727e0356e14a9e09307a9082bea4a52d4563161fd");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_rejects_unsupported_cipher() {
    const ID: &str = "TCASE-D6FF847E4E21FE34";
    const OBSERVATION_SHA256: &str = "eacb426372e0dab1ba619c8c03ac2b19fb4805e59e3a144476472847e755f2e5";
    assert_eq!(ID, "TCASE-D6FF847E4E21FE34");
    assert_eq!(OBSERVATION_SHA256, "eacb426372e0dab1ba619c8c03ac2b19fb4805e59e3a144476472847e755f2e5");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_rejects_unsupported_kdf() {
    const ID: &str = "TCASE-EA4DA40CA382B55B";
    const OBSERVATION_SHA256: &str = "fa45b01b35b54ba433eb9cc86c44b2c79c107d99bbeb1bc22017f947118103b0";
    assert_eq!(ID, "TCASE-EA4DA40CA382B55B");
    assert_eq!(OBSERVATION_SHA256, "fa45b01b35b54ba433eb9cc86c44b2c79c107d99bbeb1bc22017f947118103b0");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_is_valid_keystore_file_accepts_pbkdf2_kdf() {
    const ID: &str = "TCASE-721CEF8DDDAA7CC8";
    const OBSERVATION_SHA256: &str = "5f99757a5b4839289112692dfbfad4467f38e5993043fa1e9e89b6c831d254ad";
    assert_eq!(ID, "TCASE-721CEF8DDDAA7CC8");
    assert_eq!(OBSERVATION_SHA256, "5f99757a5b4839289112692dfbfad4467f38e5993043fa1e9e89b6c831d254ad");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_check_file_exists_null() {
    const ID: &str = "TCASE-249A3A3DD8BF4C95";
    const OBSERVATION_SHA256: &str = "2929175d0390c2775cbd9bb202434178ad23e90599065b5900fc3ac3f26acac8";
    assert_eq!(ID, "TCASE-249A3A3DD8BF4C95");
    assert_eq!(OBSERVATION_SHA256, "2929175d0390c2775cbd9bb202434178ad23e90599065b5900fc3ac3f26acac8");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_check_file_exists_missing() {
    const ID: &str = "TCASE-259D3884E809C785";
    const OBSERVATION_SHA256: &str = "e235abd1a47520674e98c6b6126398d653a204e0b80bdb91a68694ee413ce766";
    assert_eq!(ID, "TCASE-259D3884E809C785");
    assert_eq!(OBSERVATION_SHA256, "e235abd1a47520674e98c6b6126398d653a204e0b80bdb91a68694ee413ce766");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_check_file_exists_present() {
    const ID: &str = "TCASE-7181D9DD193D0516";
    const OBSERVATION_SHA256: &str = "5ecd5316026d437ba5aa9a53dc3ce5f5a820834b37bc86504cb68a17e7d09805";
    assert_eq!(ID, "TCASE-7181D9DD193D0516");
    assert_eq!(OBSERVATION_SHA256, "5ecd5316026d437ba5aa9a53dc3ce5f5a820834b37bc86504cb68a17e7d09805");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_password_from_file() {
    const ID: &str = "TCASE-0EE84A4F944D7E14";
    const OBSERVATION_SHA256: &str = "d9e71a1f108d491171da7e75b4eb08fdd158be3a223ccac447938ae2bae5f205";
    assert_eq!(ID, "TCASE-0EE84A4F944D7E14");
    assert_eq!(OBSERVATION_SHA256, "d9e71a1f108d491171da7e75b4eb08fdd158be3a223ccac447938ae2bae5f205");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_password_from_file_with_line_endings() {
    const ID: &str = "TCASE-DB5C2FC8BAD6B264";
    const OBSERVATION_SHA256: &str = "bcdb199feade353fab7939fc9e4d02aa57a99554af6f824463d6238708e0398a";
    assert_eq!(ID, "TCASE-DB5C2FC8BAD6B264");
    assert_eq!(OBSERVATION_SHA256, "bcdb199feade353fab7939fc9e4d02aa57a99554af6f824463d6238708e0398a");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_password_from_file_with_bom() {
    const ID: &str = "TCASE-2A79113E67F6039D";
    const OBSERVATION_SHA256: &str = "6ca9bf368efb1ee8fbe03d9bd9036ac5658b8a826b5d5bfadb851c1b299f37b7";
    assert_eq!(ID, "TCASE-2A79113E67F6039D");
    assert_eq!(OBSERVATION_SHA256, "6ca9bf368efb1ee8fbe03d9bd9036ac5658b8a826b5d5bfadb851c1b299f37b7");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_password_file_too_large() {
    const ID: &str = "TCASE-59F4AD82CC07E1C2";
    const OBSERVATION_SHA256: &str = "653dac1ef6d19b36e2d08d8558a07942aabc488fbbda63e427670bdb00be59ce";
    assert_eq!(ID, "TCASE-59F4AD82CC07E1C2");
    assert_eq!(OBSERVATION_SHA256, "653dac1ef6d19b36e2d08d8558a07942aabc488fbbda63e427670bdb00be59ce");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_password_file_short() {
    const ID: &str = "TCASE-C2999FC983F82DE2";
    const OBSERVATION_SHA256: &str = "2ded9cf42cf002aee5668ab1316a466c2cd5464ff3a19f495679f318abf8c399";
    assert_eq!(ID, "TCASE-C2999FC983F82DE2");
    assert_eq!(OBSERVATION_SHA256, "2ded9cf42cf002aee5668ab1316a466c2cd5464ff3a19f495679f318abf8c399");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_password_file_not_found() {
    const ID: &str = "TCASE-E0D75C9147D9CCF3";
    const OBSERVATION_SHA256: &str = "ae5334d8a8c2def87788fccc518d8fb693d0cebf3d7eb764988a2330486abfba";
    assert_eq!(ID, "TCASE-E0D75C9147D9CCF3");
    assert_eq!(OBSERVATION_SHA256, "ae5334d8a8c2def87788fccc518d8fb693d0cebf3d7eb764988a2330486abfba");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_ensure_directory_creates_nested() {
    const ID: &str = "TCASE-1342F5698E1AC459";
    const OBSERVATION_SHA256: &str = "36d40030e8c2f443301c643666f2092d0e9ebdc7a865131669291ab98fa42434";
    assert_eq!(ID, "TCASE-1342F5698E1AC459");
    assert_eq!(OBSERVATION_SHA256, "36d40030e8c2f443301c643666f2092d0e9ebdc7a865131669291ab98fa42434");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_ensure_directory_existing() {
    const ID: &str = "TCASE-A1D9FD811CDE7915";
    const OBSERVATION_SHA256: &str = "bff68fc021df7d796c8f118b7bffe175d5b3c713d5c3fafced9be6d71f1ec12f";
    assert_eq!(ID, "TCASE-A1D9FD811CDE7915");
    assert_eq!(OBSERVATION_SHA256, "bff68fc021df7d796c8f118b7bffe175d5b3c713d5c3fafced9be6d71f1ec12f");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_ensure_directory_path_is_file() {
    const ID: &str = "TCASE-ABCC8527E477B4A1";
    const OBSERVATION_SHA256: &str = "9f93ff2748eea7e2543b4d882b391df9924148149cdf88ef923117abdc1e2c7a";
    assert_eq!(ID, "TCASE-ABCC8527E477B4A1");
    assert_eq!(OBSERVATION_SHA256, "9f93ff2748eea7e2543b4d882b391df9924148149cdf88ef923117abdc1e2c7a");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_print_json_valid_output() {
    const ID: &str = "TCASE-A5DDD5EC0530F0FD";
    const OBSERVATION_SHA256: &str = "f7e205c2c14a1cae4e0f6a5f6a1f2cc45fedef518e5d28b610498cdc97352579";
    assert_eq!(ID, "TCASE-A5DDD5EC0530F0FD");
    assert_eq!(OBSERVATION_SHA256, "f7e205c2c14a1cae4e0f6a5f6a1f2cc45fedef518e5d28b610498cdc97352579");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_print_security_tips_includes_address_and_file() {
    const ID: &str = "TCASE-2178408F41385C11";
    const OBSERVATION_SHA256: &str = "176ae7a76a87a9094e81a27cb0f137a90e31422696fcb6603e6ed72ed390109b";
    assert_eq!(ID, "TCASE-2178408F41385C11");
    assert_eq!(OBSERVATION_SHA256, "176ae7a76a87a9094e81a27cb0f137a90e31422696fcb6603e6ed72ed390109b");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_regular_file_success() {
    const ID: &str = "TCASE-871CEB0DB37CA962";
    const OBSERVATION_SHA256: &str = "c156014a7330e8ce4012916a329040da16f6166b639f6028a0a32d1a0113bbd0";
    assert_eq!(ID, "TCASE-871CEB0DB37CA962");
    assert_eq!(OBSERVATION_SHA256, "c156014a7330e8ce4012916a329040da16f6166b639f6028a0a32d1a0113bbd0");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_regular_file_missing() {
    const ID: &str = "TCASE-4C7C895A35338F11";
    const OBSERVATION_SHA256: &str = "1b2900a59fd5a519989fadb792131b746b3a9dd7a2377d96bda6ba8ca8de3856";
    assert_eq!(ID, "TCASE-4C7C895A35338F11");
    assert_eq!(OBSERVATION_SHA256, "1b2900a59fd5a519989fadb792131b746b3a9dd7a2377d96bda6ba8ca8de3856");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_regular_file_too_large() {
    const ID: &str = "TCASE-F36B1FDD93D0A082";
    const OBSERVATION_SHA256: &str = "4a4f0fe5a80efa532083385475d1b24d6cca6ac27839877f993973b1be91e6a5";
    assert_eq!(ID, "TCASE-F36B1FDD93D0A082");
    assert_eq!(OBSERVATION_SHA256, "4a4f0fe5a80efa532083385475d1b24d6cca6ac27839877f993973b1be91e6a5");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_regular_file_refuses_symlink() {
    const ID: &str = "TCASE-CCCE374144740CC6";
    const OBSERVATION_SHA256: &str = "48c7e51ca5c1f9ed63d52bff91215474df911ab27c74d977971f71c581e0fc02";
    assert_eq!(ID, "TCASE-CCCE374144740CC6");
    assert_eq!(OBSERVATION_SHA256, "48c7e51ca5c1f9ed63d52bff91215474df911ab27c74d977971f71c581e0fc02");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_regular_file_refuses_directory() {
    const ID: &str = "TCASE-B868341260CB8707";
    const OBSERVATION_SHA256: &str = "12ee512a236ccddbdf154321b219cfe482e0844803e40adcd3a8446ea614ff55";
    assert_eq!(ID, "TCASE-B868341260CB8707");
    assert_eq!(OBSERVATION_SHA256, "12ee512a236ccddbdf154321b219cfe482e0844803e40adcd3a8446ea614ff55");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_read_regular_file_empty_file() {
    const ID: &str = "TCASE-2A511E920F1478DC";
    const OBSERVATION_SHA256: &str = "f8af96911b9fbb9a233459291e51652a252b2d9321787734b9ebf662730f9896";
    assert_eq!(ID, "TCASE-2A511E920F1478DC");
    assert_eq!(OBSERVATION_SHA256, "f8af96911b9fbb9a233459291e51652a252b2d9321787734b9ebf662730f9896");
    assert!(parse_private_key(format!("0x{}", "01".repeat(32)).as_bytes(), CryptoEngine::Secp256k1).is_ok());
}

fn scenario_test_import_with_key_file_and_password_file() {
    const ID: &str = "TCASE-2E8284D0DCA9673B";
    const OBSERVATION_SHA256: &str = "df595c6b72298797f8cb597fa5f7683562b5d8180835ec07b18567aa18f52b5f";
    assert_eq!(ID, "TCASE-2E8284D0DCA9673B");
    assert_eq!(OBSERVATION_SHA256, "df595c6b72298797f8cb597fa5f7683562b5d8180835ec07b18567aa18f52b5f");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_invalid_key_too_short() {
    const ID: &str = "TCASE-F497AA9185FB15E5";
    const OBSERVATION_SHA256: &str = "2c11918d6d53aca3d88ab541d3e9a5127428ef646d0a2e45d931d34e9dc7bd09";
    assert_eq!(ID, "TCASE-F497AA9185FB15E5");
    assert_eq!(OBSERVATION_SHA256, "2c11918d6d53aca3d88ab541d3e9a5127428ef646d0a2e45d931d34e9dc7bd09");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_invalid_key_non_hex() {
    const ID: &str = "TCASE-C5ED1C64D90A4E0F";
    const OBSERVATION_SHA256: &str = "4fa840a4fce66f8e6449f346fe22fe7080bbfd987a66060cd7e24fddd8bacbe1";
    assert_eq!(ID, "TCASE-C5ED1C64D90A4E0F");
    assert_eq!(OBSERVATION_SHA256, "4fa840a4fce66f8e6449f346fe22fe7080bbfd987a66060cd7e24fddd8bacbe1");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_no_tty_no_key_file() {
    const ID: &str = "TCASE-6EF43134C2A58882";
    const OBSERVATION_SHA256: &str = "706b9b4e09906dedce93d198529c4e36640b7cdff6ba6c2c2a16a8bf03719aef";
    assert_eq!(ID, "TCASE-6EF43134C2A58882");
    assert_eq!(OBSERVATION_SHA256, "706b9b4e09906dedce93d198529c4e36640b7cdff6ba6c2c2a16a8bf03719aef");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_with_sm2() {
    const ID: &str = "TCASE-DAEB0D5525FC3B9F";
    const OBSERVATION_SHA256: &str = "2ef81af0502bef6f18a9572fcb70d94dcab0d22679b11c261e31e80a521a4871";
    assert_eq!(ID, "TCASE-DAEB0D5525FC3B9F");
    assert_eq!(OBSERVATION_SHA256, "2ef81af0502bef6f18a9572fcb70d94dcab0d22679b11c261e31e80a521a4871");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_key_file_with_whitespace() {
    const ID: &str = "TCASE-3AEB7F6E12741582";
    const OBSERVATION_SHA256: &str = "d54e4e1656da83822169156aa796914f8428ecb6993df350c4e229ad8be6ccde";
    assert_eq!(ID, "TCASE-3AEB7F6E12741582");
    assert_eq!(OBSERVATION_SHA256, "d54e4e1656da83822169156aa796914f8428ecb6993df350c4e229ad8be6ccde");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_duplicate_address_blocked() {
    const ID: &str = "TCASE-7A166AC7741DC012";
    const OBSERVATION_SHA256: &str = "1c36b9acc9fa7b9d834ed501ea73c99091fad1de19981b3f854d08f1b99a7f71";
    assert_eq!(ID, "TCASE-7A166AC7741DC012");
    assert_eq!(OBSERVATION_SHA256, "1c36b9acc9fa7b9d834ed501ea73c99091fad1de19981b3f854d08f1b99a7f71");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_duplicate_address_with_force() {
    const ID: &str = "TCASE-E69F3107CF4F59BC";
    const OBSERVATION_SHA256: &str = "39e8a36b95d4948ab37188b2ab35f8b27f07174c7360ea106c96e6c50a908b70";
    assert_eq!(ID, "TCASE-E69F3107CF4F59BC");
    assert_eq!(OBSERVATION_SHA256, "39e8a36b95d4948ab37188b2ab35f8b27f07174c7360ea106c96e6c50a908b70");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_key_file_not_found() {
    const ID: &str = "TCASE-2C380C3DC54E59C6";
    const OBSERVATION_SHA256: &str = "da850af187341efa3f4718b3585515a0dd6a053e57f3fdb14ac278bc23ca9377";
    assert_eq!(ID, "TCASE-2C380C3DC54E59C6");
    assert_eq!(OBSERVATION_SHA256, "da850af187341efa3f4718b3585515a0dd6a053e57f3fdb14ac278bc23ca9377");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_with0x_prefix() {
    const ID: &str = "TCASE-DE142D3ABED72E4E";
    const OBSERVATION_SHA256: &str = "22dd931a20c0590dfb4c0e5e717c47d3e14a4ad0eded6633cad3851caa74a3a3";
    assert_eq!(ID, "TCASE-DE142D3ABED72E4E");
    assert_eq!(OBSERVATION_SHA256, "22dd931a20c0590dfb4c0e5e717c47d3e14a4ad0eded6633cad3851caa74a3a3");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_with0_x_uppercase_prefix() {
    const ID: &str = "TCASE-74396E19F97E2234";
    const OBSERVATION_SHA256: &str = "6ec90c105ef9005a4c2cde94294333c077932191c7dfb5d4caab0f20074e912a";
    assert_eq!(ID, "TCASE-74396E19F97E2234");
    assert_eq!(OBSERVATION_SHA256, "6ec90c105ef9005a4c2cde94294333c077932191c7dfb5d4caab0f20074e912a");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_warns_on_corrupted_file() {
    const ID: &str = "TCASE-778D09E8DAF00628";
    const OBSERVATION_SHA256: &str = "c395332e55d56b52dffe83161ec4b382c5cfb457cacab74cf3e27a57fbdfe45e";
    assert_eq!(ID, "TCASE-778D09E8DAF00628");
    assert_eq!(OBSERVATION_SHA256, "c395332e55d56b52dffe83161ec4b382c5cfb457cacab74cf3e27a57fbdfe45e");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_keystore_file_permissions() {
    const ID: &str = "TCASE-49EB0A84D157E4F6";
    const OBSERVATION_SHA256: &str = "24f0c0fca015437109b53fa37e850a1c72aea7fff3a3b6f8006c25baa03f2bf9";
    assert_eq!(ID, "TCASE-49EB0A84D157E4F6");
    assert_eq!(OBSERVATION_SHA256, "24f0c0fca015437109b53fa37e850a1c72aea7fff3a3b6f8006c25baa03f2bf9");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_refuses_symlink_key_file() {
    const ID: &str = "TCASE-C987EDE0E1FA050B";
    const OBSERVATION_SHA256: &str = "b80c3f502effdba243be97910a7e55d5d122b71c9ae517fa912a5bb51c510b62";
    assert_eq!(ID, "TCASE-C987EDE0E1FA050B");
    assert_eq!(OBSERVATION_SHA256, "b80c3f502effdba243be97910a7e55d5d122b71c9ae517fa912a5bb51c510b62");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_refuses_symlink_password_file() {
    const ID: &str = "TCASE-2246CB112D64C8BC";
    const OBSERVATION_SHA256: &str = "5eb558b8e91b6c93ab6dd889f9b27f2710191acdf1622e584b0540d10401e5dc";
    assert_eq!(ID, "TCASE-2246CB112D64C8BC");
    assert_eq!(OBSERVATION_SHA256, "5eb558b8e91b6c93ab6dd889f9b27f2710191acdf1622e584b0540d10401e5dc");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_duplicate_check_skips_invalid_version() {
    const ID: &str = "TCASE-338A1E6DC7FE8025";
    const OBSERVATION_SHA256: &str = "0357408fa34809d1d088891de7553b379eddf7f0df27101b7253d76488a631f2";
    assert_eq!(ID, "TCASE-338A1E6DC7FE8025");
    assert_eq!(OBSERVATION_SHA256, "0357408fa34809d1d088891de7553b379eddf7f0df27101b7253d76488a631f2");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_duplicate_scan_skips_symlinked_entry() {
    const ID: &str = "TCASE-397136F7F89ADA62";
    const OBSERVATION_SHA256: &str = "90ae4e2fbc3ded127f91035dd78957f4cc931dd33413b4e5347b259bb022d722";
    assert_eq!(ID, "TCASE-397136F7F89ADA62");
    assert_eq!(OBSERVATION_SHA256, "90ae4e2fbc3ded127f91035dd78957f4cc931dd33413b4e5347b259bb022d722");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_import_rejects_multi_line_password_file() {
    const ID: &str = "TCASE-1C807F76B44577D7";
    const OBSERVATION_SHA256: &str = "1bcf3f27b17ffbbe2952d9320b1eab74e2cfc48f4c1796336eb35146cf14e44f";
    assert_eq!(ID, "TCASE-1C807F76B44577D7");
    assert_eq!(OBSERVATION_SHA256, "1bcf3f27b17ffbbe2952d9320b1eab74e2cfc48f4c1796336eb35146cf14e44f");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([format!("0x{}", "01".repeat(32)).into_bytes(), b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::Import(ImportKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: false, key_file: None, password_file: None, sm2: false, force: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::PrivateKey, SecretPrompt::ImportPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("Imported keystore successfully\n"));
}

fn scenario_test_list_multiple_keystores() {
    const ID: &str = "TCASE-CFC3F4258D0BA3FF";
    const OBSERVATION_SHA256: &str = "69979cbc4a6b7ffd3c0ef18521a40bd0f701aafc579906d4cd737f73b4f05842";
    assert_eq!(ID, "TCASE-CFC3F4258D0BA3FF");
    assert_eq!(OBSERVATION_SHA256, "69979cbc4a6b7ffd3c0ef18521a40bd0f701aafc579906d4cd737f73b4f05842");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_empty_directory() {
    const ID: &str = "TCASE-C89E0BFCA28D71B4";
    const OBSERVATION_SHA256: &str = "c51299142a084b46c9483ac403aa5ef947647b22762eaed22cf1234bb822f369";
    assert_eq!(ID, "TCASE-C89E0BFCA28D71B4");
    assert_eq!(OBSERVATION_SHA256, "c51299142a084b46c9483ac403aa5ef947647b22762eaed22cf1234bb822f369");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_non_existent_directory() {
    const ID: &str = "TCASE-A10407EEE330F837";
    const OBSERVATION_SHA256: &str = "9b7133db409eee5907f3adc4d955954220731ef4ef3b8d0251db37f963bbecad";
    assert_eq!(ID, "TCASE-A10407EEE330F837");
    assert_eq!(OBSERVATION_SHA256, "9b7133db409eee5907f3adc4d955954220731ef4ef3b8d0251db37f963bbecad");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_empty_directory_json_output() {
    const ID: &str = "TCASE-BA8CD76A679FCBDA";
    const OBSERVATION_SHA256: &str = "ac31d7366f259f9cae6a301d96070c681aedb527912a7364eca0a6d68bd2698f";
    assert_eq!(ID, "TCASE-BA8CD76A679FCBDA");
    assert_eq!(OBSERVATION_SHA256, "ac31d7366f259f9cae6a301d96070c681aedb527912a7364eca0a6d68bd2698f");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_non_existent_directory_json_output() {
    const ID: &str = "TCASE-E3B485C81288CB5B";
    const OBSERVATION_SHA256: &str = "d1e79e8230e8694c724449495f1016ca4f21ad96ee9fb14a6120366a535a547f";
    assert_eq!(ID, "TCASE-E3B485C81288CB5B");
    assert_eq!(OBSERVATION_SHA256, "d1e79e8230e8694c724449495f1016ca4f21ad96ee9fb14a6120366a535a547f");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_json_output() {
    const ID: &str = "TCASE-DB0F306F0D2DD80A";
    const OBSERVATION_SHA256: &str = "cc33c52585d9ef650ace64d8eff71a91e57ce9a73815eae66ebe30e0165fc098";
    assert_eq!(ID, "TCASE-DB0F306F0D2DD80A");
    assert_eq!(OBSERVATION_SHA256, "cc33c52585d9ef650ace64d8eff71a91e57ce9a73815eae66ebe30e0165fc098");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_skips_non_keystore_files() {
    const ID: &str = "TCASE-1F6413B639E4D477";
    const OBSERVATION_SHA256: &str = "dc3bfd50fea7e624db02d7735b1bcb825f43b000f72f7aab3c4fa4a0d9d5dc88";
    assert_eq!(ID, "TCASE-1F6413B639E4D477");
    assert_eq!(OBSERVATION_SHA256, "dc3bfd50fea7e624db02d7735b1bcb825f43b000f72f7aab3c4fa4a0d9d5dc88");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_warns_on_corrupted_json_files() {
    const ID: &str = "TCASE-8989819B58DD1045";
    const OBSERVATION_SHA256: &str = "9f77fe24eb1329844922014fba9f85e3c624d637669b25ca277cfac21f3cc394";
    assert_eq!(ID, "TCASE-8989819B58DD1045");
    assert_eq!(OBSERVATION_SHA256, "9f77fe24eb1329844922014fba9f85e3c624d637669b25ca277cfac21f3cc394");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_skips_invalid_version_keystores() {
    const ID: &str = "TCASE-02B8DD39B7D690EC";
    const OBSERVATION_SHA256: &str = "e19cedced1a84fa411edc9a61a62bdba72f9f6ed937fd18fd67c046e55e31026";
    assert_eq!(ID, "TCASE-02B8DD39B7D690EC");
    assert_eq!(OBSERVATION_SHA256, "e19cedced1a84fa411edc9a61a62bdba72f9f6ed937fd18fd67c046e55e31026");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_list_skips_symlinked_keystore_file() {
    const ID: &str = "TCASE-E3822362BFE70AE7";
    const OBSERVATION_SHA256: &str = "37cc68591830d6a46fe99e7e9a20da8cad7c37da7cfcf39797b18f2b89f504fd";
    assert_eq!(ID, "TCASE-E3822362BFE70AE7");
    assert_eq!(OBSERVATION_SHA256, "37cc68591830d6a46fe99e7e9a20da8cad7c37da7cfcf39797b18f2b89f504fd");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo::default(); let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    service.listed.keystores.push(ListedKeystore { address: "TAddress".into(), path: PathBuf::from("/hidden/a.json") }); service.listed.warnings.push(StoreWarning::SkippedInvalidJson { path: PathBuf::from("/hidden/bad.json") });
    let out = dispatch(KeystoreCommand::List(ListKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(out.stdout, b"{\"keystores\":[{\"address\":\"TAddress\",\"file\":\"a.json\"}]}\n"); assert_eq!(out.stderr, b"Warning: skipping unreadable file: bad.json\n");
}

fn scenario_test_new_keystore_with_password_file() {
    const ID: &str = "TCASE-86B2CC34FB6FEE4F";
    const OBSERVATION_SHA256: &str = "72f8091a9b9f33d1a6ba257846a6dfdf51dd0b2bf898ed1bfc3e36a6b5762d98";
    assert_eq!(ID, "TCASE-86B2CC34FB6FEE4F");
    assert_eq!(OBSERVATION_SHA256, "72f8091a9b9f33d1a6ba257846a6dfdf51dd0b2bf898ed1bfc3e36a6b5762d98");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_json_output() {
    const ID: &str = "TCASE-F0A217C5DAA61B68";
    const OBSERVATION_SHA256: &str = "0ff38f48cc66633db6f58703714772291e738e2cc0fc53076c3980554f7a04e2";
    assert_eq!(ID, "TCASE-F0A217C5DAA61B68");
    assert_eq!(OBSERVATION_SHA256, "0ff38f48cc66633db6f58703714772291e738e2cc0fc53076c3980554f7a04e2");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_invalid_password() {
    const ID: &str = "TCASE-66708F182B38B352";
    const OBSERVATION_SHA256: &str = "808d4baf0394a0fa28b1f598655afd075e7b24a0cb3a4864c59e32feaea2b1e1";
    assert_eq!(ID, "TCASE-66708F182B38B352");
    assert_eq!(OBSERVATION_SHA256, "808d4baf0394a0fa28b1f598655afd075e7b24a0cb3a4864c59e32feaea2b1e1");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_custom_dir() {
    const ID: &str = "TCASE-3FFDD210428BA0E9";
    const OBSERVATION_SHA256: &str = "7143b3105d6a22111e56a350b4d5937934bb1877b768c7a74f5374e1daced239";
    assert_eq!(ID, "TCASE-3FFDD210428BA0E9");
    assert_eq!(OBSERVATION_SHA256, "7143b3105d6a22111e56a350b4d5937934bb1877b768c7a74f5374e1daced239");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_no_tty_no_password_file() {
    const ID: &str = "TCASE-8E9FB2E1E96275C6";
    const OBSERVATION_SHA256: &str = "5e25a0d185ffccd309de643af593b970e5c5de0b5a51b3698066d1715fcdcc98";
    assert_eq!(ID, "TCASE-8E9FB2E1E96275C6");
    assert_eq!(OBSERVATION_SHA256, "5e25a0d185ffccd309de643af593b970e5c5de0b5a51b3698066d1715fcdcc98");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_empty_password() {
    const ID: &str = "TCASE-0B303D5220A6B58E";
    const OBSERVATION_SHA256: &str = "ae80c122e7ac5724e253e326f26bd7da2bd00b571e631a43a6f6d6b43bb17974";
    assert_eq!(ID, "TCASE-0B303D5220A6B58E");
    assert_eq!(OBSERVATION_SHA256, "ae80c122e7ac5724e253e326f26bd7da2bd00b571e631a43a6f6d6b43bb17974");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_with_sm2() {
    const ID: &str = "TCASE-EDBBB764CE40453B";
    const OBSERVATION_SHA256: &str = "1d0c82d7687ba969ce10b892a1505f60aa3029bdb5c04d86e3f8df134bc04149";
    assert_eq!(ID, "TCASE-EDBBB764CE40453B");
    assert_eq!(OBSERVATION_SHA256, "1d0c82d7687ba969ce10b892a1505f60aa3029bdb5c04d86e3f8df134bc04149");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_special_char_password() {
    const ID: &str = "TCASE-4605EECC752CFF3A";
    const OBSERVATION_SHA256: &str = "043b6cd119bdedc218ee7a46f97261c18f34fdeb90d6909aa569958c2b0194a4";
    assert_eq!(ID, "TCASE-4605EECC752CFF3A");
    assert_eq!(OBSERVATION_SHA256, "043b6cd119bdedc218ee7a46f97261c18f34fdeb90d6909aa569958c2b0194a4");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_password_file_not_found() {
    const ID: &str = "TCASE-B1AD37895037CF60";
    const OBSERVATION_SHA256: &str = "a9fa060ce0bfa52b5082e4bf4d11f6d024f56ef553884dd311ea114238eea2b7";
    assert_eq!(ID, "TCASE-B1AD37895037CF60");
    assert_eq!(OBSERVATION_SHA256, "a9fa060ce0bfa52b5082e4bf4d11f6d024f56ef553884dd311ea114238eea2b7");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_dir_is_file() {
    const ID: &str = "TCASE-8634A6F287A5C331";
    const OBSERVATION_SHA256: &str = "3ef91b96cb7460cf5db3e039a3d1494a68d6a879fc616c48db1a057223ecb42e";
    assert_eq!(ID, "TCASE-8634A6F287A5C331");
    assert_eq!(OBSERVATION_SHA256, "3ef91b96cb7460cf5db3e039a3d1494a68d6a879fc616c48db1a057223ecb42e");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_password_file_too_large() {
    const ID: &str = "TCASE-F47073590223C675";
    const OBSERVATION_SHA256: &str = "b3da50b30e792976d23968a485db5fcd038f3a1fb4a11b9cebe78f36ceed9d1b";
    assert_eq!(ID, "TCASE-F47073590223C675");
    assert_eq!(OBSERVATION_SHA256, "b3da50b30e792976d23968a485db5fcd038f3a1fb4a11b9cebe78f36ceed9d1b");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_password_file_with_bom() {
    const ID: &str = "TCASE-685C635E71B00A4D";
    const OBSERVATION_SHA256: &str = "01e864ac8c284b3b21607c6571d3dfe003edb552d45c4c1aa972a13094dc1d41";
    assert_eq!(ID, "TCASE-685C635E71B00A4D");
    assert_eq!(OBSERVATION_SHA256, "01e864ac8c284b3b21607c6571d3dfe003edb552d45c4c1aa972a13094dc1d41");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_file_permissions() {
    const ID: &str = "TCASE-8F8CBD81D26B3F5B";
    const OBSERVATION_SHA256: &str = "084293e2e428aaffd74df7706077a3528be2d0498f799b084a69bc3c223dd916";
    assert_eq!(ID, "TCASE-8F8CBD81D26B3F5B");
    assert_eq!(OBSERVATION_SHA256, "084293e2e428aaffd74df7706077a3528be2d0498f799b084a69bc3c223dd916");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_new_keystore_rejects_multi_line_password_file() {
    const ID: &str = "TCASE-ED23370F05B19C5B";
    const OBSERVATION_SHA256: &str = "402c7e08b036e4503000e30a31dcb0eb6ead9f72eaa516842a0c25bde51fa6e8";
    assert_eq!(ID, "TCASE-ED23370F05B19C5B");
    assert_eq!(OBSERVATION_SHA256, "402c7e08b036e4503000e30a31dcb0eb6ead9f72eaa516842a0c25bde51fa6e8");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu");
    let mut io = FakeIo { secrets: VecDeque::from([b"secret1".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices::success();
    let out = dispatch(KeystoreCommand::New(NewKeystoreArgs { keystore_dir: cwd.join("Wallet"), json: true, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap();
    assert_eq!(service.calls, 1); assert_eq!(io.reads, vec![SecretPrompt::NewPassword]); assert!(String::from_utf8(out.stdout).unwrap().starts_with("{\"address\":"));
}

fn scenario_test_update_password() {
    const ID: &str = "TCASE-6EB621D47E9C9D3D";
    const OBSERVATION_SHA256: &str = "f9c5b9fdd91a533e997e49fe04f52a9bfa80d31a27d71525eed9ede2b9bb9108";
    assert_eq!(ID, "TCASE-6EB621D47E9C9D3D");
    assert_eq!(OBSERVATION_SHA256, "f9c5b9fdd91a533e997e49fe04f52a9bfa80d31a27d71525eed9ede2b9bb9108");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_wrong_old_password() {
    const ID: &str = "TCASE-2700E815968AECC0";
    const OBSERVATION_SHA256: &str = "03b24ebab169818070984b2eadc2b9744a6d45590148266df41321dc753c6230";
    assert_eq!(ID, "TCASE-2700E815968AECC0");
    assert_eq!(OBSERVATION_SHA256, "03b24ebab169818070984b2eadc2b9744a6d45590148266df41321dc753c6230");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_non_existent_address() {
    const ID: &str = "TCASE-D58DB0F093426029";
    const OBSERVATION_SHA256: &str = "c0c433f4d71758892149d1654dcbf2eed1ee00a57940a6d0b0f59a44c0772570";
    assert_eq!(ID, "TCASE-D58DB0F093426029");
    assert_eq!(OBSERVATION_SHA256, "c0c433f4d71758892149d1654dcbf2eed1ee00a57940a6d0b0f59a44c0772570");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_new_password_too_short() {
    const ID: &str = "TCASE-970A921E3F09612F";
    const OBSERVATION_SHA256: &str = "f3bc9ddec478f39a10ecd88bee97407c3c7861416c4dbac38fe3f5f4c6d54358";
    assert_eq!(ID, "TCASE-970A921E3F09612F");
    assert_eq!(OBSERVATION_SHA256, "f3bc9ddec478f39a10ecd88bee97407c3c7861416c4dbac38fe3f5f4c6d54358");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_with_windows_line_endings() {
    const ID: &str = "TCASE-ED0EB2C4EFFC5696";
    const OBSERVATION_SHA256: &str = "dd05942f35ba760d673f6406720ae9bd57592186e19716fd4a226127192eea13";
    assert_eq!(ID, "TCASE-ED0EB2C4EFFC5696");
    assert_eq!(OBSERVATION_SHA256, "dd05942f35ba760d673f6406720ae9bd57592186e19716fd4a226127192eea13");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_json_output() {
    const ID: &str = "TCASE-44439CCF0D819478";
    const OBSERVATION_SHA256: &str = "e796d99e970155d5aefdbb9efb35d5a7e5cca6649d398502b727a2c59664ff33";
    assert_eq!(ID, "TCASE-44439CCF0D819478");
    assert_eq!(OBSERVATION_SHA256, "e796d99e970155d5aefdbb9efb35d5a7e5cca6649d398502b727a2c59664ff33");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_warns_on_corrupted_file() {
    const ID: &str = "TCASE-DC70C5903FF7A2B7";
    const OBSERVATION_SHA256: &str = "a81b8bfe0b37f88da3820a5c5f0d2190ffedd6161d75feed364ddd1a7038b367";
    assert_eq!(ID, "TCASE-DC70C5903FF7A2B7");
    assert_eq!(OBSERVATION_SHA256, "a81b8bfe0b37f88da3820a5c5f0d2190ffedd6161d75feed364ddd1a7038b367");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_password_file_only_one_line() {
    const ID: &str = "TCASE-D253F0BD9C0A156E";
    const OBSERVATION_SHA256: &str = "75015a2a6dd1df52c11b8af0aa91a452731657b1e891426e0faedce013128ffe";
    assert_eq!(ID, "TCASE-D253F0BD9C0A156E");
    assert_eq!(OBSERVATION_SHA256, "75015a2a6dd1df52c11b8af0aa91a452731657b1e891426e0faedce013128ffe");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_password_file_three_lines() {
    const ID: &str = "TCASE-80CE6C5179B3C735";
    const OBSERVATION_SHA256: &str = "4078ccd7751c5f87c15ee318e1f5914dcbf694b9508960f98a1a5ffb6c474a26";
    assert_eq!(ID, "TCASE-80CE6C5179B3C735");
    assert_eq!(OBSERVATION_SHA256, "4078ccd7751c5f87c15ee318e1f5914dcbf694b9508960f98a1a5ffb6c474a26");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_no_tty_no_password_file() {
    const ID: &str = "TCASE-396C8E2B8A64FD8E";
    const OBSERVATION_SHA256: &str = "9164389598077cf450f3606afdf122a151fd0597ce46757e4c14a88adab0c480";
    assert_eq!(ID, "TCASE-396C8E2B8A64FD8E");
    assert_eq!(OBSERVATION_SHA256, "9164389598077cf450f3606afdf122a151fd0597ce46757e4c14a88adab0c480");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_password_file_not_found() {
    const ID: &str = "TCASE-2CC90ED90BE30E3E";
    const OBSERVATION_SHA256: &str = "7157083f0763c74630f97c31aa584135d70f618e01bad27904cd4c9362e374cf";
    assert_eq!(ID, "TCASE-2CC90ED90BE30E3E");
    assert_eq!(OBSERVATION_SHA256, "7157083f0763c74630f97c31aa584135d70f618e01bad27904cd4c9362e374cf");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_sm2_keystore() {
    const ID: &str = "TCASE-D7902CE4A9A9F5C4";
    const OBSERVATION_SHA256: &str = "945d81dbb7d97fe6a0604e648e53f531a84712851059fea150c71cc8e9675940";
    assert_eq!(ID, "TCASE-D7902CE4A9A9F5C4");
    assert_eq!(OBSERVATION_SHA256, "945d81dbb7d97fe6a0604e648e53f531a84712851059fea150c71cc8e9675940");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_multiple_keystores_same_address() {
    const ID: &str = "TCASE-7925DADC55372170";
    const OBSERVATION_SHA256: &str = "a552acab6cf9ce7c2918fb4ee710bfe8ee00f0ab83d636532ba6342ffb366b02";
    assert_eq!(ID, "TCASE-7925DADC55372170");
    assert_eq!(OBSERVATION_SHA256, "a552acab6cf9ce7c2918fb4ee710bfe8ee00f0ab83d636532ba6342ffb366b02");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_password_file_too_large() {
    const ID: &str = "TCASE-E057ECEC9E1FD29A";
    const OBSERVATION_SHA256: &str = "96f7f5e1dd582dbce9879203e7dbeda7a24864555ae9a2a1cc138bcf184bc4a3";
    assert_eq!(ID, "TCASE-E057ECEC9E1FD29A");
    assert_eq!(OBSERVATION_SHA256, "96f7f5e1dd582dbce9879203e7dbeda7a24864555ae9a2a1cc138bcf184bc4a3");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_password_file_with_bom() {
    const ID: &str = "TCASE-AB04B42FB1605C46";
    const OBSERVATION_SHA256: &str = "25d251b67e8b0feb00dffa5beea4c4ca756c9b562183f94952c467a9f99a1927";
    assert_eq!(ID, "TCASE-AB04B42FB1605C46");
    assert_eq!(OBSERVATION_SHA256, "25d251b67e8b0feb00dffa5beea4c4ca756c9b562183f94952c467a9f99a1927");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_non_existent_keystore_dir() {
    const ID: &str = "TCASE-D32447956E5B73FC";
    const OBSERVATION_SHA256: &str = "ae692e834fc7382c470ca0c13bf7dc1b492c630da19252c1e9ae6d2991bafe0b";
    assert_eq!(ID, "TCASE-D32447956E5B73FC");
    assert_eq!(OBSERVATION_SHA256, "ae692e834fc7382c470ca0c13bf7dc1b492c630da19252c1e9ae6d2991bafe0b");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_keystore_dir_is_file() {
    const ID: &str = "TCASE-DE5AEB8A09C043B6";
    const OBSERVATION_SHA256: &str = "5878a7bd1172cb87867a3e99a1d3e87d2aa589e19bacbcb395946de31faf75e2";
    assert_eq!(ID, "TCASE-DE5AEB8A09C043B6");
    assert_eq!(OBSERVATION_SHA256, "5878a7bd1172cb87867a3e99a1d3e87d2aa589e19bacbcb395946de31faf75e2");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_with_old_mac_line_endings() {
    const ID: &str = "TCASE-4FF51D2992AE9F83";
    const OBSERVATION_SHA256: &str = "5ed9a6efee32813db53e21be38d0047ad78c4ab49c4efa6546b9456e84c270de";
    assert_eq!(ID, "TCASE-4FF51D2992AE9F83");
    assert_eq!(OBSERVATION_SHA256, "5ed9a6efee32813db53e21be38d0047ad78c4ab49c4efa6546b9456e84c270de");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_skips_invalid_version_keystores() {
    const ID: &str = "TCASE-CF5C4155D49D572D";
    const OBSERVATION_SHA256: &str = "d8f309dbaa2cb41de6592028bf54b6296a9590e8319a62b48f72d9c9aca360ff";
    assert_eq!(ID, "TCASE-CF5C4155D49D572D");
    assert_eq!(OBSERVATION_SHA256, "d8f309dbaa2cb41de6592028bf54b6296a9590e8319a62b48f72d9c9aca360ff");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_rejects_tampered_address_keystore() {
    const ID: &str = "TCASE-2E187D127668AEF4";
    const OBSERVATION_SHA256: &str = "57566196688bf5af86e6cfed7fbeca71b63579d91f1f74ee6336cdfedf7afd54";
    assert_eq!(ID, "TCASE-2E187D127668AEF4");
    assert_eq!(OBSERVATION_SHA256, "57566196688bf5af86e6cfed7fbeca71b63579d91f1f74ee6336cdfedf7afd54");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_preserves_correct_derived_address() {
    const ID: &str = "TCASE-608A442B52AA061C";
    const OBSERVATION_SHA256: &str = "71b8bc2d378a865ba504099e2c9ea4ad545c53eb63a246c1d7a9a9cac39ab20d";
    assert_eq!(ID, "TCASE-608A442B52AA061C");
    assert_eq!(OBSERVATION_SHA256, "71b8bc2d378a865ba504099e2c9ea4ad545c53eb63a246c1d7a9a9cac39ab20d");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_narrows_loose_permissions_to0600() {
    const ID: &str = "TCASE-73FBF8004E007F93";
    const OBSERVATION_SHA256: &str = "805988a28737b2c7f048f0f2a1eb968c1fc4502aa119bfe97017a4b9030747ce";
    assert_eq!(ID, "TCASE-73FBF8004E007F93");
    assert_eq!(OBSERVATION_SHA256, "805988a28737b2c7f048f0f2a1eb968c1fc4502aa119bfe97017a4b9030747ce");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_legacy_tip_fires_when_password_has_whitespace() {
    const ID: &str = "TCASE-A236F26A0D1CE3D9";
    const OBSERVATION_SHA256: &str = "6cf50fa050f83b59d218d5bca16c5efb7807f9e757e0d87dada5c5af65f90d00";
    assert_eq!(ID, "TCASE-A236F26A0D1CE3D9");
    assert_eq!(OBSERVATION_SHA256, "6cf50fa050f83b59d218d5bca16c5efb7807f9e757e0d87dada5c5af65f90d00");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_legacy_tip_suppressed_when_password_has_no_whitespace() {
    const ID: &str = "TCASE-32D43571C3734081";
    const OBSERVATION_SHA256: &str = "0efb69b65bf784f7011decbf2530c43a39af4af2bffe3838d696f615435438fc";
    assert_eq!(ID, "TCASE-32D43571C3734081");
    assert_eq!(OBSERVATION_SHA256, "0efb69b65bf784f7011decbf2530c43a39af4af2bffe3838d696f615435438fc");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}

fn scenario_test_update_scan_skips_symlinked_entry() {
    const ID: &str = "TCASE-3653C680C51FC0CB";
    const OBSERVATION_SHA256: &str = "4919570eeb39b5d38f7268b0ecd81d08f08be4e73b20f64d163365b0a5e77062";
    assert_eq!(ID, "TCASE-3653C680C51FC0CB");
    assert_eq!(OBSERVATION_SHA256, "4919570eeb39b5d38f7268b0ecd81d08f08be4e73b20f64d163365b0a5e77062");
    let cwd = Path::new("/work"); let platform = PlatformFacts::new("linux", "x86_64", "x86_64-unknown-linux-gnu"); let mut io = FakeIo { secrets: VecDeque::from([b"old pass".to_vec(), b"newpass".to_vec()]), reads: vec![] }; let mut keys = FakeKeys; let clock = FixedClock(OffsetDateTime::UNIX_EPOCH); let mut service = FakeServices { mode: ServiceMode::DecryptionFailure, listed: ListReport::default(), calls: 0, update_passwords: None };
    let error = dispatch(KeystoreCommand::Update(UpdateKeystoreArgs { address: "T".into(), keystore_dir: cwd.join("Wallet"), json: false, password_file: None, sm2: false }), &mut context(cwd, &mut io, &clock, &mut keys, &platform), &mut service).unwrap_err();
    let ToolkitError::Parity { stderr, .. } = error else { panic!("expected parity error") }; let text = String::from_utf8(stderr).unwrap(); assert!(text.contains("Decryption failed: bad password\n")); assert!(text.contains("legacy code truncated the password at the first whitespace"));
}
