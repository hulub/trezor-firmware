/* Automatically generated nanopb header */
/* Generated by nanopb-0.2.9.3 */

#ifndef _PB_TYPES_PB_H_
#define _PB_TYPES_PB_H_
#include "pb.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _FailureType {
    FailureType_Failure_UnexpectedMessage = 1,
    FailureType_Failure_ButtonExpected = 2,
    FailureType_Failure_SyntaxError = 3,
    FailureType_Failure_ActionCancelled = 4,
    FailureType_Failure_PinExpected = 5,
    FailureType_Failure_PinCancelled = 6,
    FailureType_Failure_PinInvalid = 7,
    FailureType_Failure_InvalidSignature = 8,
    FailureType_Failure_Other = 9,
    FailureType_Failure_NotEnoughFunds = 10,
    FailureType_Failure_NotInitialized = 11,
    FailureType_Failure_FirmwareError = 99
} FailureType;

typedef enum _OutputScriptType {
    OutputScriptType_PAYTOADDRESS = 0,
    OutputScriptType_PAYTOSCRIPTHASH = 1,
    OutputScriptType_PAYTOMULTISIG = 2,
    OutputScriptType_PAYTOOPRETURN = 3,
    OutputScriptType_PAYTOWITNESS = 4,
    OutputScriptType_PAYTOP2SHWITNESS = 5
} OutputScriptType;

typedef enum _InputScriptType {
    InputScriptType_SPENDADDRESS = 0,
    InputScriptType_SPENDMULTISIG = 1,
    InputScriptType_EXTERNAL = 2,
    InputScriptType_SPENDWITNESS = 3,
    InputScriptType_SPENDP2SHWITNESS = 4
} InputScriptType;

typedef enum _RequestType {
    RequestType_TXINPUT = 0,
    RequestType_TXOUTPUT = 1,
    RequestType_TXMETA = 2,
    RequestType_TXFINISHED = 3,
    RequestType_TXEXTRADATA = 4
} RequestType;

typedef enum _ButtonRequestType {
    ButtonRequestType_ButtonRequest_Other = 1,
    ButtonRequestType_ButtonRequest_FeeOverThreshold = 2,
    ButtonRequestType_ButtonRequest_ConfirmOutput = 3,
    ButtonRequestType_ButtonRequest_ResetDevice = 4,
    ButtonRequestType_ButtonRequest_ConfirmWord = 5,
    ButtonRequestType_ButtonRequest_WipeDevice = 6,
    ButtonRequestType_ButtonRequest_ProtectCall = 7,
    ButtonRequestType_ButtonRequest_SignTx = 8,
    ButtonRequestType_ButtonRequest_FirmwareCheck = 9,
    ButtonRequestType_ButtonRequest_Address = 10,
    ButtonRequestType_ButtonRequest_PublicKey = 11
} ButtonRequestType;

typedef enum _PinMatrixRequestType {
    PinMatrixRequestType_PinMatrixRequestType_Current = 1,
    PinMatrixRequestType_PinMatrixRequestType_NewFirst = 2,
    PinMatrixRequestType_PinMatrixRequestType_NewSecond = 3
} PinMatrixRequestType;

typedef enum _RecoveryDeviceType {
    RecoveryDeviceType_RecoveryDeviceType_ScrambledWords = 0,
    RecoveryDeviceType_RecoveryDeviceType_Matrix = 1
} RecoveryDeviceType;

typedef enum _WordRequestType {
    WordRequestType_WordRequestType_Plain = 0,
    WordRequestType_WordRequestType_Matrix9 = 1,
    WordRequestType_WordRequestType_Matrix6 = 2
} WordRequestType;

/* Struct definitions */
typedef struct _CoinType {
    bool has_coin_name;
    char coin_name[17];
    bool has_coin_shortcut;
    char coin_shortcut[9];
    bool has_address_type;
    uint32_t address_type;
    bool has_maxfee_kb;
    uint64_t maxfee_kb;
    bool has_address_type_p2sh;
    uint32_t address_type_p2sh;
    bool has_address_type_p2wpkh;
    uint32_t address_type_p2wpkh;
    bool has_address_type_p2wsh;
    uint32_t address_type_p2wsh;
    bool has_signed_message_header;
    char signed_message_header[32];
} CoinType;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} DiscreteLogarithmEqualityPKType_commitment1_t;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} DiscreteLogarithmEqualityPKType_commitment2_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DiscreteLogarithmEqualityPKType_challenge_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DiscreteLogarithmEqualityPKType_response_t;

typedef struct _DiscreteLogarithmEqualityPKType {
    DiscreteLogarithmEqualityPKType_commitment1_t commitment1;
    DiscreteLogarithmEqualityPKType_commitment2_t commitment2;
    DiscreteLogarithmEqualityPKType_challenge_t challenge;
    DiscreteLogarithmEqualityPKType_response_t response;
} DiscreteLogarithmEqualityPKType;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} DiscreteLogarithmPKType_commitment_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DiscreteLogarithmPKType_challenge_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} DiscreteLogarithmPKType_response_t;

typedef struct _DiscreteLogarithmPKType {
    DiscreteLogarithmPKType_commitment_t commitment;
    DiscreteLogarithmPKType_challenge_t challenge;
    DiscreteLogarithmPKType_response_t response;
} DiscreteLogarithmPKType;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} ElGamalTupleType_R_t;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} ElGamalTupleType_C_t;

typedef struct _ElGamalTupleType {
    ElGamalTupleType_R_t R;
    ElGamalTupleType_C_t C;
} ElGamalTupleType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} HDNodeType_chain_code_t;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} HDNodeType_private_key_t;

typedef struct {
    size_t size;
    uint8_t bytes[33];
} HDNodeType_public_key_t;

typedef struct _HDNodeType {
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    HDNodeType_chain_code_t chain_code;
    bool has_private_key;
    HDNodeType_private_key_t private_key;
    bool has_public_key;
    HDNodeType_public_key_t public_key;
} HDNodeType;

typedef struct _IdentityType {
    bool has_proto;
    char proto[9];
    bool has_user;
    char user[64];
    bool has_host;
    char host[64];
    bool has_port;
    char port[6];
    bool has_path;
    char path[256];
    bool has_index;
    uint32_t index;
} IdentityType;

typedef struct {
    size_t size;
    uint8_t bytes[520];
} TxOutputBinType_script_pubkey_t;

typedef struct _TxOutputBinType {
    uint64_t amount;
    TxOutputBinType_script_pubkey_t script_pubkey;
} TxOutputBinType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} TxRequestDetailsType_tx_hash_t;

typedef struct _TxRequestDetailsType {
    bool has_request_index;
    uint32_t request_index;
    bool has_tx_hash;
    TxRequestDetailsType_tx_hash_t tx_hash;
    bool has_extra_data_len;
    uint32_t extra_data_len;
    bool has_extra_data_offset;
    uint32_t extra_data_offset;
} TxRequestDetailsType;

typedef struct {
    size_t size;
    uint8_t bytes[73];
} TxRequestSerializedType_signature_t;

typedef struct {
    size_t size;
    uint8_t bytes[2048];
} TxRequestSerializedType_serialized_tx_t;

typedef struct _TxRequestSerializedType {
    bool has_signature_index;
    uint32_t signature_index;
    bool has_signature;
    TxRequestSerializedType_signature_t signature;
    bool has_serialized_tx;
    TxRequestSerializedType_serialized_tx_t serialized_tx;
} TxRequestSerializedType;

typedef struct _HDNodePathType {
    HDNodeType node;
    size_t address_n_count;
    uint32_t address_n[8];
} HDNodePathType;

typedef struct {
    size_t size;
    uint8_t bytes[73];
} MultisigRedeemScriptType_signatures_t;

typedef struct _MultisigRedeemScriptType {
    size_t pubkeys_count;
    HDNodePathType pubkeys[15];
    size_t signatures_count;
    MultisigRedeemScriptType_signatures_t signatures[15];
    bool has_m;
    uint32_t m;
} MultisigRedeemScriptType;

typedef struct {
    size_t size;
    uint8_t bytes[32];
} TxInputType_prev_hash_t;

typedef struct {
    size_t size;
    uint8_t bytes[1650];
} TxInputType_script_sig_t;

typedef struct _TxInputType {
    size_t address_n_count;
    uint32_t address_n[8];
    TxInputType_prev_hash_t prev_hash;
    uint32_t prev_index;
    bool has_script_sig;
    TxInputType_script_sig_t script_sig;
    bool has_sequence;
    uint32_t sequence;
    bool has_script_type;
    InputScriptType script_type;
    bool has_multisig;
    MultisigRedeemScriptType multisig;
    bool has_amount;
    uint64_t amount;
} TxInputType;

typedef struct {
    size_t size;
    uint8_t bytes[80];
} TxOutputType_op_return_data_t;

typedef struct _TxOutputType {
    bool has_address;
    char address[41];
    size_t address_n_count;
    uint32_t address_n[8];
    uint64_t amount;
    OutputScriptType script_type;
    bool has_multisig;
    MultisigRedeemScriptType multisig;
    bool has_op_return_data;
    TxOutputType_op_return_data_t op_return_data;
} TxOutputType;

typedef struct {
    size_t size;
    uint8_t bytes[1024];
} TransactionType_extra_data_t;

typedef struct _TransactionType {
    bool has_version;
    uint32_t version;
    size_t inputs_count;
    TxInputType inputs[1];
    size_t bin_outputs_count;
    TxOutputBinType bin_outputs[1];
    bool has_lock_time;
    uint32_t lock_time;
    size_t outputs_count;
    TxOutputType outputs[1];
    bool has_inputs_cnt;
    uint32_t inputs_cnt;
    bool has_outputs_cnt;
    uint32_t outputs_cnt;
    bool has_extra_data;
    TransactionType_extra_data_t extra_data;
    bool has_extra_data_len;
    uint32_t extra_data_len;
} TransactionType;

/* Extensions */
extern const pb_extension_type_t wire_in;
extern const pb_extension_type_t wire_out;
extern const pb_extension_type_t wire_debug_in;
extern const pb_extension_type_t wire_debug_out;

/* Default values for struct fields */
extern const uint32_t CoinType_address_type_default;
extern const uint32_t CoinType_address_type_p2sh_default;
extern const uint32_t CoinType_address_type_p2wpkh_default;
extern const uint32_t CoinType_address_type_p2wsh_default;
extern const uint32_t TxInputType_sequence_default;
extern const InputScriptType TxInputType_script_type_default;
extern const uint32_t IdentityType_index_default;

/* Initializer values for message structs */
#define ElGamalTupleType_init_default            {{0, {0}}, {0, {0}}}
#define DiscreteLogarithmEqualityPKType_init_default {{0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}}
#define DiscreteLogarithmPKType_init_default     {{0, {0}}, {0, {0}}, {0, {0}}}
#define HDNodeType_init_default                  {0, 0, 0, {0, {0}}, false, {0, {0}}, false, {0, {0}}}
#define HDNodePathType_init_default              {HDNodeType_init_default, 0, {0, 0, 0, 0, 0, 0, 0, 0}}
#define CoinType_init_default                    {false, "", false, "", false, 0u, false, 0, false, 5u, false, 6u, false, 10u, false, ""}
#define MultisigRedeemScriptType_init_default    {0, {HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default, HDNodePathType_init_default}, 0, {{0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}}, false, 0}
#define TxInputType_init_default                 {0, {0, 0, 0, 0, 0, 0, 0, 0}, {0, {0}}, 0, false, {0, {0}}, false, 4294967295u, false, InputScriptType_SPENDADDRESS, false, MultisigRedeemScriptType_init_default, false, 0}
#define TxOutputType_init_default                {false, "", 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, (OutputScriptType)0, false, MultisigRedeemScriptType_init_default, false, {0, {0}}}
#define TxOutputBinType_init_default             {0, {0, {0}}}
#define TransactionType_init_default             {false, 0, 0, {TxInputType_init_default}, 0, {TxOutputBinType_init_default}, false, 0, 0, {TxOutputType_init_default}, false, 0, false, 0, false, {0, {0}}, false, 0}
#define TxRequestDetailsType_init_default        {false, 0, false, {0, {0}}, false, 0, false, 0}
#define TxRequestSerializedType_init_default     {false, 0, false, {0, {0}}, false, {0, {0}}}
#define IdentityType_init_default                {false, "", false, "", false, "", false, "", false, "", false, 0u}
#define ElGamalTupleType_init_zero               {{0, {0}}, {0, {0}}}
#define DiscreteLogarithmEqualityPKType_init_zero {{0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}}
#define DiscreteLogarithmPKType_init_zero        {{0, {0}}, {0, {0}}, {0, {0}}}
#define HDNodeType_init_zero                     {0, 0, 0, {0, {0}}, false, {0, {0}}, false, {0, {0}}}
#define HDNodePathType_init_zero                 {HDNodeType_init_zero, 0, {0, 0, 0, 0, 0, 0, 0, 0}}
#define CoinType_init_zero                       {false, "", false, "", false, 0, false, 0, false, 0, false, 0, false, 0, false, ""}
#define MultisigRedeemScriptType_init_zero       {0, {HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero, HDNodePathType_init_zero}, 0, {{0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}, {0, {0}}}, false, 0}
#define TxInputType_init_zero                    {0, {0, 0, 0, 0, 0, 0, 0, 0}, {0, {0}}, 0, false, {0, {0}}, false, 0, false, (InputScriptType)0, false, MultisigRedeemScriptType_init_zero, false, 0}
#define TxOutputType_init_zero                   {false, "", 0, {0, 0, 0, 0, 0, 0, 0, 0}, 0, (OutputScriptType)0, false, MultisigRedeemScriptType_init_zero, false, {0, {0}}}
#define TxOutputBinType_init_zero                {0, {0, {0}}}
#define TransactionType_init_zero                {false, 0, 0, {TxInputType_init_zero}, 0, {TxOutputBinType_init_zero}, false, 0, 0, {TxOutputType_init_zero}, false, 0, false, 0, false, {0, {0}}, false, 0}
#define TxRequestDetailsType_init_zero           {false, 0, false, {0, {0}}, false, 0, false, 0}
#define TxRequestSerializedType_init_zero        {false, 0, false, {0, {0}}, false, {0, {0}}}
#define IdentityType_init_zero                   {false, "", false, "", false, "", false, "", false, "", false, 0}

/* Field tags (for use in manual encoding/decoding) */
#define CoinType_coin_name_tag                   1
#define CoinType_coin_shortcut_tag               2
#define CoinType_address_type_tag                3
#define CoinType_maxfee_kb_tag                   4
#define CoinType_address_type_p2sh_tag           5
#define CoinType_address_type_p2wpkh_tag         6
#define CoinType_address_type_p2wsh_tag          7
#define CoinType_signed_message_header_tag       8
#define DiscreteLogarithmEqualityPKType_commitment1_tag 1
#define DiscreteLogarithmEqualityPKType_commitment2_tag 2
#define DiscreteLogarithmEqualityPKType_challenge_tag 3
#define DiscreteLogarithmEqualityPKType_response_tag 4
#define DiscreteLogarithmPKType_commitment_tag   1
#define DiscreteLogarithmPKType_challenge_tag    2
#define DiscreteLogarithmPKType_response_tag     3
#define ElGamalTupleType_R_tag                   1
#define ElGamalTupleType_C_tag                   2
#define HDNodeType_depth_tag                     1
#define HDNodeType_fingerprint_tag               2
#define HDNodeType_child_num_tag                 3
#define HDNodeType_chain_code_tag                4
#define HDNodeType_private_key_tag               5
#define HDNodeType_public_key_tag                6
#define IdentityType_proto_tag                   1
#define IdentityType_user_tag                    2
#define IdentityType_host_tag                    3
#define IdentityType_port_tag                    4
#define IdentityType_path_tag                    5
#define IdentityType_index_tag                   6
#define TxOutputBinType_amount_tag               1
#define TxOutputBinType_script_pubkey_tag        2
#define TxRequestDetailsType_request_index_tag   1
#define TxRequestDetailsType_tx_hash_tag         2
#define TxRequestDetailsType_extra_data_len_tag  3
#define TxRequestDetailsType_extra_data_offset_tag 4
#define TxRequestSerializedType_signature_index_tag 1
#define TxRequestSerializedType_signature_tag    2
#define TxRequestSerializedType_serialized_tx_tag 3
#define HDNodePathType_node_tag                  1
#define HDNodePathType_address_n_tag             2
#define MultisigRedeemScriptType_pubkeys_tag     1
#define MultisigRedeemScriptType_signatures_tag  2
#define MultisigRedeemScriptType_m_tag           3
#define TxInputType_address_n_tag                1
#define TxInputType_prev_hash_tag                2
#define TxInputType_prev_index_tag               3
#define TxInputType_script_sig_tag               4
#define TxInputType_sequence_tag                 5
#define TxInputType_script_type_tag              6
#define TxInputType_multisig_tag                 7
#define TxInputType_amount_tag                   8
#define TxOutputType_address_tag                 1
#define TxOutputType_address_n_tag               2
#define TxOutputType_amount_tag                  3
#define TxOutputType_script_type_tag             4
#define TxOutputType_multisig_tag                5
#define TxOutputType_op_return_data_tag          6
#define TransactionType_version_tag              1
#define TransactionType_inputs_tag               2
#define TransactionType_bin_outputs_tag          3
#define TransactionType_outputs_tag              5
#define TransactionType_lock_time_tag            4
#define TransactionType_inputs_cnt_tag           6
#define TransactionType_outputs_cnt_tag          7
#define TransactionType_extra_data_tag           8
#define TransactionType_extra_data_len_tag       9
#define wire_in_tag                              50002
#define wire_out_tag                             50003
#define wire_debug_in_tag                        50004
#define wire_debug_out_tag                       50005

/* Struct field encoding specification for nanopb */
extern const pb_field_t ElGamalTupleType_fields[3];
extern const pb_field_t DiscreteLogarithmEqualityPKType_fields[5];
extern const pb_field_t DiscreteLogarithmPKType_fields[4];
extern const pb_field_t HDNodeType_fields[7];
extern const pb_field_t HDNodePathType_fields[3];
extern const pb_field_t CoinType_fields[9];
extern const pb_field_t MultisigRedeemScriptType_fields[4];
extern const pb_field_t TxInputType_fields[9];
extern const pb_field_t TxOutputType_fields[7];
extern const pb_field_t TxOutputBinType_fields[3];
extern const pb_field_t TransactionType_fields[10];
extern const pb_field_t TxRequestDetailsType_fields[5];
extern const pb_field_t TxRequestSerializedType_fields[4];
extern const pb_field_t IdentityType_fields[7];

/* Maximum encoded size of messages (where known) */
#define ElGamalTupleType_size                    70
#define DiscreteLogarithmEqualityPKType_size     138
#define DiscreteLogarithmPKType_size             103
#define HDNodeType_size                          121
#define HDNodePathType_size                      171
#define CoinType_size                            99
#define MultisigRedeemScriptType_size            3741
#define TxInputType_size                         5508
#define TxOutputType_size                        3934
#define TxOutputBinType_size                     534
#define TransactionType_size                     11042
#define TxRequestDetailsType_size                52
#define TxRequestSerializedType_size             2132
#define IdentityType_size                        416

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
