/*
    This is a KeyListener project file
    Developer: CyberMor <cyber.mor.2020@gmail.com>

    See more here https://github.com/CyberMor/keylistener

    Copyright (c) Daniel (CyberMor) 2020 All rights reserved
*/

#pragma once

#include <cstdint>
#include <cstddef>
#include <climits>

// ----------------------------------------------------------------

// requirement : byte = 8 bits
// requirement : word = 2 bytes

using sbyte_t = std::int8_t;    // signed byte
using ubyte_t = std::uint8_t;   // unsigned byte

using sword_t = std::int16_t;   // signed word
using uword_t = std::uint16_t;  // unsigned word

using sdword_t = std::int32_t;  // signed double word
using udword_t = std::uint32_t; // unsigned double word

using sqword_t = std::int64_t;  // signed quad word
using uqword_t = std::uint64_t; // unsigned quad word

using fdword_t = float;         // floating double word
using fqword_t = double;        // floating quad word

// ----------------------------------------------------------------

#ifndef CHAR_BIT
#error failed to determine byte size
#endif

static_assert(CHAR_BIT == 8, "invalid 'byte' size");

// ----------------------------------------------------------------

static_assert(sizeof(sbyte_t) == 1, "invalid 'sbyte_t' size");
static_assert(sizeof(ubyte_t) == 1, "invalid 'ubyte_t' size");

static_assert(sizeof(sword_t) == 2, "invalid 'sword_t' size");
static_assert(sizeof(uword_t) == 2, "invalid 'uword_t' size");

static_assert(sizeof(sdword_t) == 4, "invalid 'sdword_t' size");
static_assert(sizeof(udword_t) == 4, "invalid 'udword_t' size");

static_assert(sizeof(sqword_t) == 8, "invalid 'sqword_t' size");
static_assert(sizeof(uqword_t) == 8, "invalid 'uqword_t' size");

static_assert(sizeof(fdword_t) == 4, "invalid 'fdword_t' size");
static_assert(sizeof(fqword_t) == 8, "invalid 'fqword_t' size");

// ----------------------------------------------------------------

using sint_t = signed int;        // signed platform-specific word
using uint_t = unsigned int;      // unsigned platform-specific word

using size_t = std::size_t;       // platform-specific size type (unsigned)

using  ptr_t = void*;             // universal pointer type
using cptr_t = const void*;       // const universal pointer type

using  adr_t = ubyte_t*;          // memory address type
using cadr_t = const ubyte_t*;    // const memory address type

using  str_t = char*;             // string type
using cstr_t = const char*;       // const string type
