/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "trezor.h"
#include "fsm.h"
#include "messages.h"
#include "bip32.h"
#include "storage.h"
#include "coins.h"
#include "debug.h"
#include "transaction.h"
#include "rng.h"
#include "storage.h"
#include "oled.h"
#include "protect.h"
#include "pinmatrix.h"
#include "layout2.h"
#include "ecdsa.h"
#include "reset.h"
#include "recovery.h"
#include "memory.h"
#include "usb.h"
#include "util.h"
#include "signing.h"
#include "aes.h"
#include "hmac.h"
#include "crypto.h"
#include "base58.h"
#include "bip39.h"
#include "ripemd160.h"
#include "curves.h"
#include "secp256k1.h"
#include <libopencm3/stm32/flash.h>
#include "ethereum.h"

// message methods

static uint8_t msg_resp[MSG_OUT_SIZE] __attribute__ ((aligned));

#define RESP_INIT(TYPE) \
			TYPE *resp = (TYPE *) (void *) msg_resp; \
			_Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
			memset(resp, 0, sizeof(TYPE));

#define CHECK_INITIALIZED \
	if (!storage_isInitialized()) { \
		fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized"); \
		return; \
	}

#define CHECK_NOT_INITIALIZED \
	if (storage_isInitialized()) { \
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Device is already initialized. Use Wipe first."); \
		return; \
	}

#define CHECK_PIN \
	if (!protectPin(true)) { \
		layoutHome(); \
		return; \
	}

#define CHECK_PIN_UNCACHED \
	if (!protectPin(false)) { \
		layoutHome(); \
		return; \
	}

#define CHECK_PARAM(cond, errormsg) \
	if (!(cond)) { \
		fsm_sendFailure(FailureType_Failure_SyntaxError, (errormsg)); \
		layoutHome(); \
		return; \
	}

void fsm_sendSuccess(const char *text) {
	RESP_INIT(Success);
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char *text) {
	if (protectAbortedByInitialize) {
		fsm_msgInitialize((Initialize *) 0);
		protectAbortedByInitialize = false;
		return;
	}
	RESP_INIT(Failure);
	resp->has_code = true;
	resp->code = code;
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Failure, resp);
}

const CoinType *fsm_getCoin(const char *name) {
	const CoinType *coin = coinByName(name);
	if (!coin) {
		fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
		layoutHome();
		return 0;
	}
	return coin;
}

HDNode *fsm_getDerivedNode(const char *curve, uint32_t *address_n,
		size_t address_n_count) {
	static HDNode node;
	if (!storage_getRootNode(&node, curve, true)) {
		fsm_sendFailure(FailureType_Failure_NotInitialized,
				"Device not initialized or passphrase request cancelled or unsupported curve");
		layoutHome();
		return 0;
	}
	if (!address_n || address_n_count == 0) {
		return &node;
	}
	if (hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL)
			== 0) {
		fsm_sendFailure(FailureType_Failure_Other,
				"Failed to derive private key");
		layoutHome();
		return 0;
	}
	return &node;
}

void fsm_msgInitialize(Initialize *msg) {
	(void) msg;
	recovery_abort();
	signing_abort();
	session_clear(false); // do not clear PIN
	layoutHome();
	fsm_msgGetFeatures(0);
}

void fsm_msgGetFeatures(GetFeatures *msg) {
	(void) msg;
	RESP_INIT(Features);
	resp->has_vendor = true;
	strlcpy(resp->vendor, "bitcointrezor.com", sizeof(resp->vendor));
	resp->has_major_version = true;
	resp->major_version = VERSION_MAJOR;
	resp->has_minor_version = true;
	resp->minor_version = VERSION_MINOR;
	resp->has_patch_version = true;
	resp->patch_version = VERSION_PATCH;
	resp->has_device_id = true;
	strlcpy(resp->device_id, storage_uuid_str, sizeof(resp->device_id));
	resp->has_pin_protection = true;
	resp->pin_protection = storage.has_pin;
	resp->has_passphrase_protection = true;
	resp->passphrase_protection = storage.has_passphrase_protection
			&& storage.passphrase_protection;
#ifdef SCM_REVISION
	int len = sizeof(SCM_REVISION) - 1;
	resp->has_revision = true; memcpy(resp->revision.bytes, SCM_REVISION, len); resp->revision.size = len;
#endif
	resp->has_bootloader_hash = true;
	resp->bootloader_hash.size = memory_bootloader_hash(
			resp->bootloader_hash.bytes);
	if (storage.has_language) {
		resp->has_language = true;
		strlcpy(resp->language, storage.language, sizeof(resp->language));
	}
	if (storage.has_label) {
		resp->has_label = true;
		strlcpy(resp->label, storage.label, sizeof(resp->label));
	}
	resp->coins_count = COINS_COUNT;
	memcpy(resp->coins, coins, COINS_COUNT * sizeof(CoinType));
	resp->has_initialized = true;
	resp->initialized = storage_isInitialized();
	resp->has_imported = true;
	resp->imported = storage.has_imported && storage.imported;
	resp->has_pin_cached = true;
	resp->pin_cached = session_isPinCached();
	resp->has_passphrase_cached = true;
	resp->passphrase_cached = session_isPassphraseCached();
	msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(Ping *msg) {
	RESP_INIT(Success);

	if (msg->has_button_protection && msg->button_protection) {
		layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
				"Do you really want to", "answer to ping?", NULL, NULL, NULL,
				NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Ping cancelled");
			layoutHome();
			return;
		}
	}

	if (msg->has_pin_protection && msg->pin_protection) {
		CHECK_PIN
	}

	if (msg->has_passphrase_protection && msg->passphrase_protection) {
		if (!protectPassphrase()) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Ping cancelled");
			return;
		}
	}

	if (msg->has_message) {
		resp->has_message = true;
		memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
	layoutHome();
}

void fsm_msgChangePin(ChangePin *msg) {
	bool removal = msg->has_remove && msg->remove;
	if (removal) {
		if (storage_hasPin()) {
			layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
					"Do you really want to", "remove current PIN?", NULL, NULL,
					NULL, NULL);
		} else {
			fsm_sendSuccess("PIN removed");
			return;
		}
	} else {
		if (storage_hasPin()) {
			layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
					"Do you really want to", "change current PIN?", NULL, NULL,
					NULL, NULL);
		} else {
			layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
					"Do you really want to", "set new PIN?", NULL, NULL, NULL,
					NULL);
		}
	}
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				removal ? "PIN removal cancelled" : "PIN change cancelled");
		layoutHome();
		return;
	}

	CHECK_PIN_UNCACHED

	if (removal) {
		storage_setPin(0);
		fsm_sendSuccess("PIN removed");
	} else {
		if (protectChangePin()) {
			fsm_sendSuccess("PIN changed");
		} else {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"PIN change failed");
		}
	}
	layoutHome();
}

void fsm_msgWipeDevice(WipeDevice *msg) {
	(void) msg;
	layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
			"Do you really want to", "wipe the device?", NULL,
			"All data will be lost.", NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
		layoutHome();
		return;
	}
	storage_reset();
	storage_reset_uuid();
	storage_commit();
	storage_clearPinArea();
	// the following does not work on Mac anyway :-/ Linux/Windows are fine, so it is not needed
	// usbReconnect(); // force re-enumeration because of the serial number change
	fsm_sendSuccess("Device wiped");
	layoutHome();
}

void fsm_msgFirmwareErase(FirmwareErase *msg) {
	(void) msg;
	fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
			"Not in bootloader mode");
}

void fsm_msgFirmwareUpload(FirmwareUpload *msg) {
	(void) msg;
	fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
			"Not in bootloader mode");
}

void fsm_msgGetEntropy(GetEntropy *msg) {
	layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
			"Do you really want to", "send entropy?", NULL, NULL, NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Entropy cancelled");
		layoutHome();
		return;
	}
	RESP_INIT(Entropy);
	uint32_t len = msg->size;
	if (len > 1024) {
		len = 1024;
	}
	resp->entropy.size = len;
	random_buffer(resp->entropy.bytes, len);
	msg_write(MessageType_MessageType_Entropy, resp);
	layoutHome();
}

void fsm_msgGetPublicKey(GetPublicKey *msg) {
	RESP_INIT(PublicKey);

	CHECK_INITIALIZED

	CHECK_PIN

	const char *curve = SECP256K1_NAME;
	if (msg->has_ecdsa_curve_name) {
		curve = msg->ecdsa_curve_name;
	}
	uint32_t fingerprint;
	HDNode *node;
	if (msg->address_n_count == 0) {
		/* get master node */
		fingerprint = 0;
		node = fsm_getDerivedNode(curve, msg->address_n, 0);
	} else {
		/* get parent node */
		node = fsm_getDerivedNode(curve, msg->address_n,
				msg->address_n_count - 1);
		if (!node)
			return;
		fingerprint = hdnode_fingerprint(node);
		/* get child */
		hdnode_private_ckd(node, msg->address_n[msg->address_n_count - 1]);
	}
	hdnode_fill_public_key(node);

	if (msg->has_show_display && msg->show_display) {
		layoutCurvePoint(node->public_key, "Y");
		if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Show public key cancelled");
			layoutHome();
			return;
		}
	}

	resp->node.depth = node->depth;
	resp->node.fingerprint = fingerprint;
	resp->node.child_num = node->child_num;
	resp->node.chain_code.size = 32;
	memcpy(resp->node.chain_code.bytes, node->chain_code, 32);
	resp->node.has_private_key = false;
	resp->node.has_public_key = true;
	resp->node.public_key.size = 33;
	memcpy(resp->node.public_key.bytes, node->public_key, 33);
	if (node->public_key[0] == 1) {
		/* ed25519 public key */
		resp->node.public_key.bytes[0] = 0;
	}
	resp->has_xpub = true;
	hdnode_serialize_public(node, fingerprint, resp->xpub, sizeof(resp->xpub));
	msg_write(MessageType_MessageType_PublicKey, resp);
	layoutHome();
}

void fsm_msgLoadDevice(LoadDevice *msg) {
	CHECK_NOT_INITIALIZED

	layoutDialogSwipe(&bmp_icon_question, "Cancel", "I take the risk", NULL,
			"Loading private seed", "is not recommended.",
			"Continue only if you", "know what you are", "doing!", NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Load cancelled");
		layoutHome();
		return;
	}

	if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum)) {
		if (!mnemonic_check(msg->mnemonic)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Mnemonic with wrong checksum provided");
			layoutHome();
			return;
		}
	}

	storage_loadDevice(msg);
	storage_commit();
	fsm_sendSuccess("Device loaded");
	layoutHome();
}

void fsm_msgResetDevice(ResetDevice *msg) {
	CHECK_NOT_INITIALIZED

	CHECK_PARAM(
			!msg->has_strength || msg->strength == 128 || msg->strength == 192
					|| msg->strength == 256, "Invalid seed strength");

	reset_init(msg->has_display_random && msg->display_random,
			msg->has_strength ? msg->strength : 128,
			msg->has_passphrase_protection && msg->passphrase_protection,
			msg->has_pin_protection && msg->pin_protection,
			msg->has_language ? msg->language : 0,
			msg->has_label ? msg->label : 0,
			msg->has_u2f_counter ? msg->u2f_counter : 0);
}

void fsm_msgSignTx(SignTx *msg) {
	CHECK_INITIALIZED

	CHECK_PARAM(msg->inputs_count > 0,
			"Transaction must have at least one input");
	CHECK_PARAM(msg->outputs_count > 0,
			"Transaction must have at least one output");

	CHECK_PIN

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, 0, 0);
	if (!node)
		return;

	signing_init(msg->inputs_count, msg->outputs_count, coin, node,
			msg->version, msg->lock_time);
}

void fsm_msgTxAck(TxAck *msg) {
	CHECK_PARAM(msg->has_tx, "No transaction provided");

	signing_txack(&(msg->tx));
}

void fsm_msgCancel(Cancel *msg) {
	(void) msg;
	recovery_abort();
	signing_abort();
	ethereum_signing_abort();
	fsm_sendFailure(FailureType_Failure_ActionCancelled, "Aborted");
}

void fsm_msgEthereumSignTx(EthereumSignTx *msg) {
	CHECK_INITIALIZED

	CHECK_PIN

	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	ethereum_signing_init(msg, node);
}

void fsm_msgEthereumTxAck(EthereumTxAck *msg) {
	ethereum_signing_txack(msg);
}

void fsm_msgCipherKeyValue(CipherKeyValue *msg) {
	CHECK_INITIALIZED

	CHECK_PARAM(msg->has_key, "No key provided");
	CHECK_PARAM(msg->has_value, "No value provided");
	CHECK_PARAM(msg->value.size % 16 == 0,
			"Value length must be a multiple of 16");

	CHECK_PIN

	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	bool encrypt = msg->has_encrypt && msg->encrypt;
	bool ask_on_encrypt = msg->has_ask_on_encrypt && msg->ask_on_encrypt;
	bool ask_on_decrypt = msg->has_ask_on_decrypt && msg->ask_on_decrypt;
	if ((encrypt && ask_on_encrypt) || (!encrypt && ask_on_decrypt)) {
		layoutCipherKeyValue(encrypt, msg->key);
		if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"CipherKeyValue cancelled");
			layoutHome();
			return;
		}
	}

	uint8_t data[256 + 4];
	strlcpy((char *) data, msg->key, sizeof(data));
	strlcat((char *) data, ask_on_encrypt ? "E1" : "E0", sizeof(data));
	strlcat((char *) data, ask_on_decrypt ? "D1" : "D0", sizeof(data));

	hmac_sha512(node->private_key, 32, data, strlen((char *) data), data);

	RESP_INIT(CipheredKeyValue);
	if (encrypt) {
		aes_encrypt_ctx ctx;
		aes_encrypt_key256(data, &ctx);
		aes_cbc_encrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
				((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
	} else {
		aes_decrypt_ctx ctx;
		aes_decrypt_key256(data, &ctx);
		aes_cbc_decrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
				((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
	}
	resp->has_value = true;
	resp->value.size = msg->value.size;
	msg_write(MessageType_MessageType_CipheredKeyValue, resp);
	layoutHome();
}

void fsm_msgClearSession(ClearSession *msg) {
	(void) msg;
	session_clear(true); // clear PIN as well
	layoutScreensaver();
	fsm_sendSuccess("Session cleared");
}

void fsm_msgApplySettings(ApplySettings *msg) {
	CHECK_PARAM(
			msg->has_label || msg->has_language || msg->has_use_passphrase
					|| msg->has_homescreen, "No setting provided");

	CHECK_PIN

	if (msg->has_label) {
		layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
				"Do you really want to", "change label to", msg->label, "?",
				NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (msg->has_language) {
		layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
				"Do you really want to", "change language to", msg->language,
				"?", NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (msg->has_use_passphrase) {
		layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
				"Do you really want to",
				msg->use_passphrase ?
						"enable passphrase" : "disable passphrase",
				"encryption?", NULL, NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}
	if (msg->has_homescreen) {
		layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
				"Do you really want to", "change the home", "screen ?", NULL,
				NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall,
		false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Apply settings cancelled");
			layoutHome();
			return;
		}
	}

	if (msg->has_label) {
		storage_setLabel(msg->label);
	}
	if (msg->has_language) {
		storage_setLanguage(msg->language);
	}
	if (msg->has_use_passphrase) {
		storage_setPassphraseProtection(msg->use_passphrase);
	}
	if (msg->has_homescreen) {
		storage_setHomescreen(msg->homescreen.bytes, msg->homescreen.size);
	}
	storage_commit();
	fsm_sendSuccess("Settings applied");
	layoutHome();
}

void fsm_msgGetAddress(GetAddress *msg) {
	RESP_INIT(Address);

	CHECK_INITIALIZED

	CHECK_PIN

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
			msg->address_n_count);
	if (!node)
		return;
	hdnode_fill_public_key(node);

	if (msg->has_multisig) {
		layoutProgressSwipe("Preparing", 0);
		if (cryptoMultisigPubkeyIndex(&(msg->multisig), node->public_key) < 0) {
			fsm_sendFailure(FailureType_Failure_Other,
					"Pubkey not found in multisig script");
			layoutHome();
			return;
		}
		uint8_t buf[32];
		if (compile_script_multisig_hash(&(msg->multisig), buf) == 0) {
			fsm_sendFailure(FailureType_Failure_Other,
					"Invalid multisig script");
			layoutHome();
			return;
		}
		ripemd160(buf, 32, buf + 1);
		buf[0] = coin->address_type_p2sh; // multisig cointype
		base58_encode_check(buf, 21, resp->address, sizeof(resp->address));
	} else {
		ecdsa_get_address(node->public_key, coin->address_type, resp->address,
				sizeof(resp->address));
	}

	if (msg->has_show_display && msg->show_display) {
		char desc[16];
		if (msg->has_multisig) {
			strlcpy(desc, "Msig __ of __:", sizeof(desc));
			const uint32_t m = msg->multisig.m;
			const uint32_t n = msg->multisig.pubkeys_count;
			desc[5] = (m < 10) ? ' ' : ('0' + (m / 10));
			desc[6] = '0' + (m % 10);
			desc[11] = (n < 10) ? ' ' : ('0' + (n / 10));
			desc[12] = '0' + (n % 10);
		} else {
			strlcpy(desc, "Address:", sizeof(desc));
		}
		layoutAddress(resp->address, desc);
		if (!protectButton(ButtonRequestType_ButtonRequest_Address, true)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Show address cancelled");
			layoutHome();
			return;
		}
	}

	msg_write(MessageType_MessageType_Address, resp);
	layoutHome();
}

void fsm_msgEthereumGetAddress(EthereumGetAddress *msg) {
	RESP_INIT(EthereumAddress);

	CHECK_INITIALIZED

	CHECK_PIN

	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	resp->address.size = 20;

	if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes))
		return;

	if (msg->has_show_display && msg->show_display) {
		char desc[16];
		strlcpy(desc, "Address:", sizeof(desc));

		char address[41];
		data2hex(resp->address.bytes, 20, address);

		layoutAddress(address, desc);
		if (!protectButton(ButtonRequestType_ButtonRequest_Address, true)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Show address cancelled");
			layoutHome();
			return;
		}
	}

	msg_write(MessageType_MessageType_EthereumAddress, resp);
	layoutHome();
}

void fsm_msgEntropyAck(EntropyAck *msg) {
	if (msg->has_entropy) {
		reset_entropy(msg->entropy.bytes, msg->entropy.size);
	} else {
		reset_entropy(0, 0);
	}
}

void fsm_msgSignMessage(SignMessage *msg) {
	RESP_INIT(MessageSignature);

	CHECK_INITIALIZED

	layoutSignMessage(msg->message.bytes, msg->message.size);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Sign message cancelled");
		layoutHome();
		return;
	}

	CHECK_PIN

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
			msg->address_n_count);
	if (!node)
		return;

	layoutProgressSwipe("Signing", 0);
	if (cryptoMessageSign(coin, node, msg->message.bytes, msg->message.size,
			resp->signature.bytes) == 0) {
		resp->has_address = true;
		hdnode_get_address(node, coin->address_type, resp->address,
				sizeof(resp->address));
		resp->has_signature = true;
		resp->signature.size = 65;
		msg_write(MessageType_MessageType_MessageSignature, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other, "Error signing message");
	}
	layoutHome();
}

void fsm_msgVerifyMessage(VerifyMessage *msg) {
	CHECK_PARAM(msg->has_address, "No address provided");
	CHECK_PARAM(msg->has_message, "No message provided");

	const CoinType *coin = fsm_getCoin(msg->coin_name);
	if (!coin)
		return;
	uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
	uint32_t address_type;
	if (!coinExtractAddressType(coin, msg->address, &address_type)
			|| !ecdsa_address_decode(msg->address, address_type, addr_raw)) {
		fsm_sendFailure(FailureType_Failure_InvalidSignature,
				"Invalid address");
		return;
	}
	layoutProgressSwipe("Verifying", 0);
	if (msg->signature.size == 65
			&& cryptoMessageVerify(coin, msg->message.bytes, msg->message.size,
					address_type, addr_raw, msg->signature.bytes) == 0) {
		layoutVerifyAddress(msg->address);
		if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Message verification cancelled");
			layoutHome();
			return;
		}
		layoutVerifyMessage(msg->message.bytes, msg->message.size);
		if (!protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled,
					"Message verification cancelled");
			layoutHome();
			return;
		}
		fsm_sendSuccess("Message verified");
	} else {
		fsm_sendFailure(FailureType_Failure_InvalidSignature,
				"Invalid signature");
	}
	layoutHome();
}

void fsm_msgSignIdentity(SignIdentity *msg) {
	RESP_INIT(SignedIdentity);

	CHECK_INITIALIZED

	layoutSignIdentity(&(msg->identity),
			msg->has_challenge_visual ? msg->challenge_visual : 0);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Sign identity cancelled");
		layoutHome();
		return;
	}

	CHECK_PIN

	uint8_t hash[32];
	if (!msg->has_identity
			|| cryptoIdentityFingerprint(&(msg->identity), hash) == 0) {
		fsm_sendFailure(FailureType_Failure_Other, "Invalid identity");
		layoutHome();
		return;
	}

	uint32_t address_n[5];
	address_n[0] = 0x80000000 | 13;
	address_n[1] = 0x80000000 | hash[0] | (hash[1] << 8) | (hash[2] << 16)
			| (hash[3] << 24);
	address_n[2] = 0x80000000 | hash[4] | (hash[5] << 8) | (hash[6] << 16)
			| (hash[7] << 24);
	address_n[3] = 0x80000000 | hash[8] | (hash[9] << 8) | (hash[10] << 16)
			| (hash[11] << 24);
	address_n[4] = 0x80000000 | hash[12] | (hash[13] << 8) | (hash[14] << 16)
			| (hash[15] << 24);

	const char *curve = SECP256K1_NAME;
	if (msg->has_ecdsa_curve_name) {
		curve = msg->ecdsa_curve_name;
	}
	HDNode *node = fsm_getDerivedNode(curve, address_n, 5);
	if (!node)
		return;

	bool sign_ssh = msg->identity.has_proto
			&& (strcmp(msg->identity.proto, "ssh") == 0);
	bool sign_gpg = msg->identity.has_proto
			&& (strcmp(msg->identity.proto, "gpg") == 0);

	int result = 0;
	layoutProgressSwipe("Signing", 0);
	if (sign_ssh) { // SSH does not sign visual challenge
		result = sshMessageSign(node, msg->challenge_hidden.bytes,
				msg->challenge_hidden.size, resp->signature.bytes);
	} else if (sign_gpg) { // GPG should sign a message digest
		result = gpgMessageSign(node, msg->challenge_hidden.bytes,
				msg->challenge_hidden.size, resp->signature.bytes);
	} else {
		uint8_t digest[64];
		sha256_Raw(msg->challenge_hidden.bytes, msg->challenge_hidden.size,
				digest);
		sha256_Raw((const uint8_t *) msg->challenge_visual,
				strlen(msg->challenge_visual), digest + 32);
		result = cryptoMessageSign(&(coins[0]), node, digest, 64,
				resp->signature.bytes);
	}

	if (result == 0) {
		hdnode_fill_public_key(node);
		if (strcmp(curve, SECP256K1_NAME) != 0) {
			resp->has_address = false;
		} else {
			resp->has_address = true;
			hdnode_get_address(node, 0x00, resp->address,
					sizeof(resp->address)); // hardcoded Bitcoin address type
		}
		resp->has_public_key = true;
		resp->public_key.size = 33;
		memcpy(resp->public_key.bytes, node->public_key, 33);
		if (node->public_key[0] == 1) {
			/* ed25519 public key */
			resp->public_key.bytes[0] = 0;
		}
		resp->has_signature = true;
		resp->signature.size = 65;
		msg_write(MessageType_MessageType_SignedIdentity, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other, "Error signing identity");
	}
	layoutHome();
}

void fsm_msgGetECDHSessionKey(GetECDHSessionKey *msg) {
	RESP_INIT(ECDHSessionKey);

	CHECK_INITIALIZED

	layoutDecryptIdentity(&msg->identity);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"ECDH Session cancelled");
		layoutHome();
		return;
	}

	CHECK_PIN

	uint8_t hash[32];
	if (!msg->has_identity
			|| cryptoIdentityFingerprint(&(msg->identity), hash) == 0) {
		fsm_sendFailure(FailureType_Failure_Other, "Invalid identity");
		layoutHome();
		return;
	}

	uint32_t address_n[5];
	address_n[0] = 0x80000000 | 17;
	address_n[1] = 0x80000000 | hash[0] | (hash[1] << 8) | (hash[2] << 16)
			| (hash[3] << 24);
	address_n[2] = 0x80000000 | hash[4] | (hash[5] << 8) | (hash[6] << 16)
			| (hash[7] << 24);
	address_n[3] = 0x80000000 | hash[8] | (hash[9] << 8) | (hash[10] << 16)
			| (hash[11] << 24);
	address_n[4] = 0x80000000 | hash[12] | (hash[13] << 8) | (hash[14] << 16)
			| (hash[15] << 24);

	const char *curve = SECP256K1_NAME;
	if (msg->has_ecdsa_curve_name) {
		curve = msg->ecdsa_curve_name;
	}

	const HDNode *node = fsm_getDerivedNode(curve, address_n, 5);
	if (!node)
		return;

	int result_size = 0;
	if (hdnode_get_shared_key(node, msg->peer_public_key.bytes,
			resp->session_key.bytes, &result_size) == 0) {
		resp->has_session_key = true;
		resp->session_key.size = result_size;
		msg_write(MessageType_MessageType_ECDHSessionKey, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other,
				"Error getting ECDH session key");
	}
	layoutHome();
}

/* ECIES disabled
 void fsm_msgEncryptMessage(EncryptMessage *msg)
 {
 CHECK_INITIALIZED

 CHECK_PARAM(msg->has_pubkey, "No public key provided");
 CHECK_PARAM(msg->has_message, "No message provided");
 CHECK_PARAM(msg->pubkey.size == 33, "Invalid public key provided");
 curve_point pubkey;
 CHECK_PARAM(ecdsa_read_pubkey(&secp256k1, msg->pubkey.bytes, &pubkey) == 1, "Invalid public key provided");

 bool display_only = msg->has_display_only && msg->display_only;
 bool signing = msg->address_n_count > 0;
 RESP_INIT(EncryptedMessage);
 const HDNode *node = 0;
 uint8_t address_raw[MAX_ADDR_RAW_SIZE];
 if (signing) {
 const CoinType *coin = fsm_getCoin(msg->coin_name);
 if (!coin) return;

 CHECK_PIN

 node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count);
 if (!node) return;
 hdnode_get_address_raw(node, coin->address_type, address_raw);
 }
 layoutEncryptMessage(msg->message.bytes, msg->message.size, signing);
 if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
 fsm_sendFailure(FailureType_Failure_ActionCancelled, "Encrypt message cancelled");
 layoutHome();
 return;
 }
 layoutProgressSwipe("Encrypting", 0);
 if (cryptoMessageEncrypt(&pubkey, msg->message.bytes, msg->message.size, display_only, resp->nonce.bytes, &(resp->nonce.size), resp->message.bytes, &(resp->message.size), resp->hmac.bytes, &(resp->hmac.size), signing ? node->private_key : 0, signing ? address_raw : 0) != 0) {
 fsm_sendFailure(FailureType_Failure_ActionCancelled, "Error encrypting message");
 layoutHome();
 return;
 }
 resp->has_nonce = true;
 resp->has_message = true;
 resp->has_hmac = true;
 msg_write(MessageType_MessageType_EncryptedMessage, resp);
 layoutHome();
 }

 void fsm_msgDecryptMessage(DecryptMessage *msg)
 {
 CHECK_INITIALIZED

 CHECK_PARAM(msg->has_nonce, "No nonce provided");
 CHECK_PARAM(msg->has_message, "No message provided");
 CHECK_PARAM(msg->has_hmac, "No message hmac provided");

 CHECK_PARAM(msg->nonce.size == 33, "Invalid nonce key provided");
 curve_point nonce_pubkey;
 CHECK_PARAM(ecdsa_read_pubkey(&secp256k1, msg->nonce.bytes, &nonce_pubkey) == 1, "Invalid nonce provided");

 CHECK_PIN

 const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count);
 if (!node) return;

 layoutProgressSwipe("Decrypting", 0);
 RESP_INIT(DecryptedMessage);
 bool display_only = false;
 bool signing = false;
 uint8_t address_raw[MAX_ADDR_RAW_SIZE];
 if (cryptoMessageDecrypt(&nonce_pubkey, msg->message.bytes, msg->message.size, msg->hmac.bytes, msg->hmac.size, node->private_key, resp->message.bytes, &(resp->message.size), &display_only, &signing, address_raw) != 0) {
 fsm_sendFailure(FailureType_Failure_ActionCancelled, "Error decrypting message");
 layoutHome();
 return;
 }
 if (signing) {
 base58_encode_check(address_raw, 21, resp->address, sizeof(resp->address));
 }
 layoutDecryptMessage(resp->message.bytes, resp->message.size, signing ? resp->address : 0);
 protectButton(ButtonRequestType_ButtonRequest_Other, true);
 if (display_only) {
 resp->has_address = false;
 resp->has_message = false;
 memset(resp->address, 0, sizeof(resp->address));
 memset(&(resp->message), 0, sizeof(resp->message));
 } else {
 resp->has_address = signing;
 resp->has_message = true;
 }
 msg_write(MessageType_MessageType_DecryptedMessage, resp);
 layoutHome();
 }
 */

void fsm_msgEstimateTxSize(EstimateTxSize *msg) {
	RESP_INIT(TxSize);
	resp->has_tx_size = true;
	resp->tx_size = transactionEstimateSize(msg->inputs_count,
			msg->outputs_count);
	msg_write(MessageType_MessageType_TxSize, resp);
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg) {
	CHECK_NOT_INITIALIZED

	CHECK_PARAM(
			!msg->has_word_count || msg->word_count == 12
					|| msg->word_count == 18 || msg->word_count == 24,
			"Invalid word count");

	recovery_init(msg->has_word_count ? msg->word_count : 12,
			msg->has_passphrase_protection && msg->passphrase_protection,
			msg->has_pin_protection && msg->pin_protection,
			msg->has_language ? msg->language : 0,
			msg->has_label ? msg->label : 0,
			msg->has_enforce_wordlist && msg->enforce_wordlist,
			msg->has_type ? msg->type : 0,
			msg->has_u2f_counter ? msg->u2f_counter : 0);
}

void fsm_msgWordAck(WordAck *msg) {
	recovery_word(msg->word);
}

void fsm_msgSetU2FCounter(SetU2FCounter *msg) {
	layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL,
			"Do you want to set", "the U2F counter?", NULL, NULL, NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"SetU2FCounter cancelled");
		layoutHome();
		return;
	}
	storage_setU2FCounter(msg->u2f_counter);
	fsm_sendSuccess("U2F counter set");
	layoutHome();
}

// test messages

void fsm_msgTestIn(TestIn *msg) {
	RESP_INIT(TestOut);

	if (msg->has_message)
		layoutDisplayMessage(msg->message, "Received message:");
	else
		layoutDisplayMessage("--no message--", "Received message:");

	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Action cancelled");
		layoutHome();
		return;
	}

	resp->has_message = true;
	strlcpy(resp->message, "Hello from Trezor", sizeof(resp->message));

	const char *desc = "testing ... ";
	layoutProgressSwipe(desc, 0);
	for (int i = 0; i < 1000; i++) {
		bignum256 x;
		generate_k_random(&x, &secp256k1.order);
		curve_point Y;
		scalar_multiply(&secp256k1, &x, &Y);

		layoutProgress(desc, i);
	}

	msg_write(MessageType_MessageType_TestOut, resp);

	layoutHome();
}

// Eos messages

void fsm_msgEosGetPublicKey(EosGetPublicKey *msg) {
	(void) msg;
	RESP_INIT(EosPublicKey);

	CHECK_INITIALIZED

	CHECK_PIN

	const char *curve = SECP256K1_NAME;

	HDNode *node;
	node = fsm_getDerivedNode(curve, NULL, 0);

	hdnode_fill_public_key(node);

	layoutCurvePoint(node->public_key, "Y");
	if (!protectButton(ButtonRequestType_ButtonRequest_PublicKey, true)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled,
				"Show public key cancelled");
		layoutHome();
		return;
	}

	resp->PublicKey.size = 33;
	memcpy(resp->PublicKey.bytes, node->public_key, 33);
	if (node->public_key[0] == 1) {
		/* ed25519 public key */
		resp->PublicKey.bytes[0] = 0;
	}

	msg_write(MessageType_MessageType_EosPublicKey, resp);
	layoutHome();
}

void fsm_msgEosVote(EosVote *msg) {
	RESP_INIT(EosVoteSignature);

	CHECK_INITIALIZED

	bool coerced = false;
	char pin[17];

	// check PIN code
	switch (protectEosPin(pin)) {
	case COERCED:
		coerced = true;
		break;
	case NOT_COERCED:
		coerced = false;
		break;
	case PIN_CANCELLED:
		fsm_sendFailure(FailureType_Failure_PinCancelled, "PIN Cancelled");
		layoutHome();
		return;
	case PIN_MISSMATCH:
		fsm_sendFailure(FailureType_Failure_PinInvalid, "PINs don't match");
		layoutHome();
		return;
	}

//	// print pin code
//	layoutDisplayMessage(pin, "pin code entered");
//	protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, true);

	// get HDNode
	const char *curve = SECP256K1_NAME;
	HDNode *node;
	node = fsm_getDerivedNode(curve, NULL, 0);
	hdnode_fill_public_key(node);

	// turn public key into point
	curve_point y_pi;
	CHECK_PARAM(ecdsa_read_pubkey(&secp256k1, node->public_key, &y_pi) == 1,
			"Invalid public key read from device");

	uint32_t i, pi = 0;
	bool pi_found = false;
	curve_point y_i, h;
	point_set_infinity(&h);

	// check my position in the ring AND compute H
	for (i = 0; i < msg->L_count; i++) {
		CHECK_PARAM(ecdsa_read_pubkey(&secp256k1, msg->L[i].bytes, &y_i) == 1,
				"Invalid public key provided in L");
		if (!pi_found)
			if (point_is_equal(&y_pi, &y_i)) {
				pi = i;
				pi_found = true;
			}

		point_add(&secp256k1, &y_i, &h);
	}

	// if pi not part of the ring
	if (!pi_found) {
		fsm_sendFailure(FailureType_Failure_Other, "Not part of the ring");
		layoutHome();
		return;
	}

	// read election key Y
	curve_point Y;
	CHECK_PARAM(ecdsa_read_pubkey(&secp256k1, msg->Y.bytes, &Y) == 1,
			"Invalid election key provided");

	// read private key
	bignum256 x_pi;
	bn_read_be(node->private_key, &x_pi);

	// pick candidate
	const char *candidate;
	while (true) {
		// display each candidate
		i = 0;
		while (true) {
			layoutDisplayCandidate(msg->candidates[i]);
			if (protectButton(ButtonRequestType_ButtonRequest_Other, false)) {
				candidate = msg->candidates[i];
				break;
			}
			i = (i + 1) % msg->candidates_count;
		}

		// confirm candidate choice
		layoutDisplayMessage(candidate, "Selected candidate:");
		if (protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false))
			break;
	}

	// turn candidate name into BigIneteger q and into a point v
	uint8_t hash[32];
	bignum256 q;
	curve_point v;
	sha256_Raw((const uint8_t *) candidate, strlen(candidate), hash);
	bn_read_be(hash, &q); 						// q is partly reduced
	bn_mod(&q, &secp256k1.order); 				// q is fully reduced
	scalar_multiply(&secp256k1, &q, &v);		// v = G*q

//	generate_k_random(&f, &secp256k1.order);
	// f should be generated using that hash function !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// f is hash( pin || priv key || h )
	bignum256 f;
	uint8_t f_encoded_bytes[strlen(pin) + 32 + 65]; // size is: size of pin + 32 (bignum) + 65 (curvepoint)
	memcpy(f_encoded_bytes, (const uint8_t *) pin, strlen(pin));
	bn_write_be(&x_pi, f_encoded_bytes + strlen(pin));
	point_encode65(&h, f_encoded_bytes + strlen(pin) + 32);
	sha256_Raw(f_encoded_bytes, strlen(pin) + 32 + 65, hash);
	bn_read_be(hash, &f);
	bn_mod(&f, &secp256k1.order);

	// encrypt h -- generate (F, phi)
	curve_point Phi, F, phi;
	point_multiply(&secp256k1, &f, &Y, &Phi);		// Phi = Y * f
	point_copy(&Phi, &phi);							// phi = Phi
	if (!coerced)
		point_add(&secp256k1, &h, &phi);		// phi = phi + h    i.e. Phi + h
	scalar_multiply(&secp256k1, &f, &F);			// F = G * f

	// encrypt y_tilde -- generate (T, theta)
	curve_point T, theta;
	point_multiply(&secp256k1, &x_pi, &F, &T);			// T = F * x_pi
	point_multiply(&secp256k1, &x_pi, &phi, &theta);	// theta = phi * x_pi

	// encrypt v -- generate (D, delta)
	bignum256 d;
	generate_k_random(&d, &secp256k1.order);
	curve_point Delta, D, delta;
	point_multiply(&secp256k1, &d, &Y, &Delta);		// Delta = Y * d
	point_copy(&v, &delta);							// delta = v
	point_add(&secp256k1, &Delta, &delta);// delta = delta + Delta    i.e. Delta + v
	scalar_multiply(&secp256k1, &d, &D);			// D = G * d

	// write (F, phi) to the response
	resp->color_enc.R.size = 33;
	point_encode33(&F, resp->color_enc.R.bytes);
	resp->color_enc.C.size = 33;
	point_encode33(&phi, resp->color_enc.C.bytes);

	// write (T, theta) to the response
	resp->eID_enc.R.size = 33;
	point_encode33(&T, resp->eID_enc.R.bytes);
	resp->eID_enc.C.size = 33;
	point_encode33(&theta, resp->eID_enc.C.bytes);

	// write (D, delta) to the response
	resp->vote_enc.R.size = 33;
	point_encode33(&D, resp->vote_enc.R.bytes);
	resp->vote_enc.C.size = 33;
	point_encode33(&delta, resp->vote_enc.C.bytes);

	// compute Discrete Logarithm Equality Zero Knowledge Proof i.e. DDH(F, phi, T, theta)
	bignum256 k;
	generate_k_random(&k, &secp256k1.order);
	curve_point Commitment1, Commitment2;
	point_multiply(&secp256k1, &k, &F, &Commitment1);
	point_multiply(&secp256k1, &k, &phi, &Commitment2);
	bignum256 challenge;
	uint8_t challenge_encoded_bytes[4 * 65];
	point_encode65(&F, challenge_encoded_bytes);
	point_encode65(&phi, challenge_encoded_bytes + 65);
	point_encode65(&Commitment1, challenge_encoded_bytes + 2 * 65);
	point_encode65(&Commitment2, challenge_encoded_bytes + 3 * 65);
	sha256_Raw(challenge_encoded_bytes, 4 * 65, hash);
	bn_read_be(hash, &challenge);
	bn_mod(&challenge, &secp256k1.order);
	bignum256 response;
	bn_copy(&challenge, &response);
	bn_multiply(&x_pi, &response, &secp256k1.order);
	bn_add(&response, &k);
	bn_fast_mod(&response, &secp256k1.order);// % order			response is partly reduced
	bn_mod(&response, &secp256k1.order);// 					response is fully reduced

	// write DLEZKP to resp
	resp->PK_correct_enc.commitment1.size = 33;
	point_encode33(&Commitment1, resp->PK_correct_enc.commitment1.bytes);
	resp->PK_correct_enc.commitment2.size = 33;
	point_encode33(&Commitment2, resp->PK_correct_enc.commitment2.bytes);
	resp->PK_correct_enc.challenge.size = 32;
	bn_write_be(&challenge, resp->PK_correct_enc.challenge.bytes);
	resp->PK_correct_enc.response.size = 32;
	bn_write_be(&response, resp->PK_correct_enc.response.bytes);

	// compute Discrete Logarithm Zero Knowledge Proof i.e. log_G D
	generate_k_random(&k, &secp256k1.order);
	curve_point Commitment;
	scalar_multiply(&secp256k1, &k, &Commitment);
	bignum256 challenge_vote;
	uint8_t challenge_vote_encoded_bytes[2 * 65];
	point_encode65(&secp256k1.G, challenge_vote_encoded_bytes);
	point_encode65(&Commitment, challenge_vote_encoded_bytes + 65);
	sha256_Raw(challenge_vote_encoded_bytes, 2 * 65, hash);
	bn_read_be(hash, &challenge_vote);
	bn_mod(&challenge_vote, &secp256k1.order);
	bignum256 response_vote;
	bn_copy(&challenge_vote, &response_vote);
	bn_multiply(&d, &response_vote, &secp256k1.order);
	bn_add(&response_vote, &k);
	bn_fast_mod(&response_vote, &secp256k1.order);// % order			response is partly reduced
	bn_mod(&response_vote, &secp256k1.order);// 					response is fully reduced

	// write DLEZKP to resp
	resp->PK_vote.commitment.size = 33;
	point_encode33(&Commitment, resp->PK_vote.commitment.bytes);
	resp->PK_vote.challenge.size = 32;
	bn_write_be(&challenge_vote, resp->PK_vote.challenge.bytes);
	resp->PK_vote.response.size = 32;
	bn_write_be(&response_vote, resp->PK_vote.response.bytes);

	// compute m = hash(R_v, V_hat) * each, encoded 65
	bignum256 m;
	uint8_t message_encoded_bytes[2 * 65];
	point_encode65(&D, message_encoded_bytes);
	point_encode65(&delta, message_encoded_bytes + 65);
	sha256_Raw(message_encoded_bytes, 2 * 65, hash);
	bn_read_be(hash, &m);
	bn_mod(&m, &secp256k1.order);

	// lsag algorithm starts here
	uint32_t progress_step = 1000 / (msg->L_count);
	uint32_t progress = 0;
	layoutProgressSwipe("Generating LSAG", progress);

	// generate u & compute first lsag encryption
	bignum256 u, c;
	generate_k_random(&u, &secp256k1.order);		// generate random u
	curve_point g_cypher, phi_cypher, temp;
	scalar_multiply(&secp256k1, &u, &g_cypher);			// g^u
	point_multiply(&secp256k1, &u, &phi, &phi_cypher);		// \phi^u

	// c = hash ( m || g^u || phi^u )
	uint8_t c_bytes[32 + 2 * 65];
	bn_write_be(&m, c_bytes);
	point_encode65(&g_cypher, c_bytes + 32);
	point_encode65(&phi_cypher, c_bytes + 32 + 65);
	sha256_Raw(c_bytes, 32 + 2 * 65, hash);
	bn_read_be(hash, &c);
	bn_mod(&c, &secp256k1.order);

//	point_copy(&g_cypher, &C);
//	point_add(&secp256k1, &phi_cypher, &C);
//	point_multiply(&secp256k1, &m, &C, &C);
//	uint8_t C_encoded[65];
//	point_encode65(&C, C_encoded);
//	sha256_Raw(C_encoded, 65, hash);


	if (pi == msg->L_count - 1) {
		// c is c_0 -- write it in the response
		resp->c1.size = 32;
		bn_write_be(&c, resp->c1.bytes);
	}

	// write s to the response
	resp->s_count = msg->L_count;

	// update progress bar
	progress = progress + progress_step;
	layoutProgress("Generating LSAG", progress);

	// do the rest of lsag encryptions in the ring
	bignum256 s;
	uint32_t index;
	for (i = 1; i < msg->L_count; i++) {

		index = (pi + i) % msg->L_count;

		generate_k_random(&s, &secp256k1.order);
		// you should write s in the resp at position index
		resp->s[index].size = 32;
		bn_write_be(&s, resp->s[index].bytes);

		// compute g_cypher = G*s + y_i*c
		// compute g_cypher = g^s * y_i^c
		scalar_multiply(&secp256k1, &s, &g_cypher);		// g_cypher = g^s
		ecdsa_read_pubkey(&secp256k1, msg->L[index].bytes, &y_i);
		point_multiply(&secp256k1, &c, &y_i, &temp);	// temp = y_i^c
		point_add(&secp256k1, &temp, &g_cypher);		// g_cypher += temp

		// compute phi_cypher = phi * s + theta * c
		// compute phi_cypher = phi^s * theta^c
		point_multiply(&secp256k1, &s, &phi, &phi_cypher);	// phi_cypher = phi^s
		point_multiply(&secp256k1, &c, &theta, &temp);		// temp = theta^c
		point_add(&secp256k1, &temp, &phi_cypher);			// phi_cypher += temp

//		// compute C = (g_cypher + phi_cypher) * m
//		point_copy(&g_cypher, &C);
//		point_add(&secp256k1, &CH, &C);
//		point_multiply(&secp256k1, &m, &C, &C);

		// compute c = hash( m || g_cypher || phi_cypher )
		bn_write_be(&m, c_bytes);
		point_encode65(&g_cypher, c_bytes + 32);
		point_encode65(&phi_cypher, c_bytes + 32 + 65);
		sha256_Raw(c_bytes, 32 + 2 * 65, hash);
		bn_read_be(hash, &c);
		bn_mod(&c, &secp256k1.order);

		if (index == msg->L_count - 1) {
			// c is c_0 -- write it in the response
			resp->c1.size = 32;
			bn_write_be(&c, resp->c1.bytes);
		}

		// update progress bar
		progress = progress + progress_step;
		layoutProgress("Generating LSAG", progress);
	}

	// compute s_pi = (u - x_pi * c_pi) % order
	bn_multiply(&x_pi, &c, &secp256k1.order);// x_pi * c_pi;		c is partly reduced
	bn_subtractmod(&u, &c, &s, &secp256k1.order);// u - ...;			s is normalized
	bn_fast_mod(&s, &secp256k1.order);	// % order			s is partly reduced
	bn_mod(&s, &secp256k1.order);		// 					s is fully reduced

	// write s to position pi
	resp->s[pi].size = 32;
	bn_write_be(&s, resp->s[pi].bytes);

	msg_write(MessageType_MessageType_EosVoteSignature, resp);
	layoutHome();
}

#if DEBUG_LINK

void fsm_msgDebugLinkGetState(DebugLinkGetState *msg)
{
	(void)msg;
	RESP_INIT(DebugLinkState);

	resp->has_layout = true;
	resp->layout.size = OLED_BUFSIZE;
	memcpy(resp->layout.bytes, oledGetBuffer(), OLED_BUFSIZE);

	if (storage.has_pin) {
		resp->has_pin = true;
		strlcpy(resp->pin, storage.pin, sizeof(resp->pin));
	}

	resp->has_matrix = true;
	strlcpy(resp->matrix, pinmatrix_get(), sizeof(resp->matrix));

	resp->has_reset_entropy = true;
	resp->reset_entropy.size = reset_get_int_entropy(resp->reset_entropy.bytes);

	resp->has_reset_word = true;
	strlcpy(resp->reset_word, reset_get_word(), sizeof(resp->reset_word));

	resp->has_recovery_fake_word = true;
	strlcpy(resp->recovery_fake_word, recovery_get_fake_word(), sizeof(resp->recovery_fake_word));

	resp->has_recovery_word_pos = true;
	resp->recovery_word_pos = recovery_get_word_pos();

	if (storage.has_mnemonic) {
		resp->has_mnemonic = true;
		strlcpy(resp->mnemonic, storage.mnemonic, sizeof(resp->mnemonic));
	}

	if (storage.has_node) {
		resp->has_node = true;
		memcpy(&(resp->node), &(storage.node), sizeof(HDNode));
	}

	resp->has_passphrase_protection = true;
	resp->passphrase_protection = storage.has_passphrase_protection && storage.passphrase_protection;

	msg_debug_write(MessageType_MessageType_DebugLinkState, resp);
}

void fsm_msgDebugLinkStop(DebugLinkStop *msg)
{
	(void)msg;
}

void fsm_msgDebugLinkMemoryRead(DebugLinkMemoryRead *msg)
{
	RESP_INIT(DebugLinkMemory);

	uint32_t length = 1024;
	if (msg->has_length && msg->length < length)
	length = msg->length;
	resp->has_memory = true;
	memcpy(resp->memory.bytes, (void*) msg->address, length);
	resp->memory.size = length;
	msg_debug_write(MessageType_MessageType_DebugLinkMemory, resp);
}

void fsm_msgDebugLinkMemoryWrite(DebugLinkMemoryWrite *msg)
{
	uint32_t length = msg->memory.size;
	if (msg->flash) {
		flash_clear_status_flags();
		flash_unlock();
		for (unsigned int i = 0; i < length; i += 4) {
			uint32_t word;
			memcpy(&word, msg->memory.bytes + i, 4);
			flash_program_word(msg->address + i, word);
		}
		flash_lock();
	} else {
		memcpy((void *) msg->address, msg->memory.bytes, length);
	}
}

void fsm_msgDebugLinkFlashErase(DebugLinkFlashErase *msg)
{
	flash_clear_status_flags();
	flash_unlock();
	flash_erase_sector(msg->sector, FLASH_CR_PROGRAM_X32);
	flash_lock();
}
#endif
