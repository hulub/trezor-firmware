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

#ifndef __PROTECT_H__
#define __PROTECT_H__

#include <stdbool.h>
#include "types.pb.h"

typedef enum {
	NOT_COERCED = 0,
	COERCED = 1,
	PIN_MISSMATCH = 2,
	PIN_CANCELLED = 3
} Coerce_State;

bool protectButton(ButtonRequestType type, bool confirm_only);
bool protectPin(bool use_cached);
bool protectChangePin(void);
bool protectPassphrase(void);
Coerce_State protectEosPin(char *pin_return);

extern bool protectAbortedByInitialize;

#endif
