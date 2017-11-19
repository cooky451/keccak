/*
 * Copyright (c) 2016 - 2017 cooky451
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef KECCAK_49206562
#define KECCAK_49206562

#include <array>
#include <cstdint>
#include <limits>

#include "keccak_detail.hpp"

namespace keccak {

/* Interface:
 * constexpr basic_memory_view() noexcept = default;
 * constexpr basic_memory_view(byte_type* data, std::size_t size) noexcept;
 *
 * template <typename Container>
 * constexpr basic_memory_view(Container& container) noexcept;
 *
 * constexpr auto& operator [] (std::size_t i) const noexcept;
 * constexpr auto data() const noexcept;
 * constexpr auto size() const noexcept;
 * constexpr auto subview(std::size_t offset) const noexcept;
 * constexpr auto subview(std::size_t offset, std::size_t size) const noexcept;
 *
 * ---- ---- ---- ---- ---- ---- ---- ----
 *
 * template <typename Container>
 * memory_view data_as_bytes(Container& container);
 *
 * template <typename Container>
 * cmemory_view data_as_bytes(const Container& container);
 */

using detail::memory_view;
using detail::cmemory_view;

using detail::data_as_bytes;

/* Interface:
 * static constexpr std::size_t collision_resistance;
 * static constexpr std::size_t preimage_resistance;
 * static constexpr std::size_t capacity;
 * static constexpr std::size_t hash_size;
 * using hash_type = std::array<std::byte, hash_size>;
 *
 * constexpr basic_hasher() noexcept = default;
 * basic_hasher(cmemory_view data) noexcept;
 * void update(cmemory_view data) noexcept;
 * void finish(memory_view buffer) noexcept;
 * hash_type finish() noexcept;
 * constexpr std::size_t byte_rate() const noexcept
 * void reset() noexcept;
 *
 * ---- ---- ---- ---- ---- ---- ---- ----
 *
 * detail::basic_hasher<x, y, z>
 * x = collision resistance
 * y = preimage resistance
 * z = domain
 *
 * ---- ---- ---- ---- ---- ---- ---- ----
 *
 * Hint for simple hashing:
 *     auto hash = shake256_hasher(data, size).finish();
 */

using sha3_244_hasher = detail::basic_hasher<112, 224, 2>;
using sha3_256_hasher = detail::basic_hasher<128, 256, 2>;
using sha3_384_hasher = detail::basic_hasher<192, 384, 2>;
using sha3_512_hasher = detail::basic_hasher<256, 512, 2>;

using shake112_hasher = detail::basic_hasher<112, 112, 15>;
using shake128_hasher = detail::basic_hasher<128, 128, 15>;
using shake192_hasher = detail::basic_hasher<192, 192, 15>;
using shake256_hasher = detail::basic_hasher<256, 256, 15>;

namespace experimental {

/* Interface:
 * using result_type = UIntType;
 * 
 * static constexpr std::size_t state_size;
 * static constexpr std::size_t security_strength;
 * static constexpr std::size_t capacity;
 *
 * basic_random_engine(cmemory_view seed) noexcept;
 * void reseed(cmemory_view seed) noexcept;
 * void extract(memory_view buffer) noexcept;
 * void operator () (memory_view buffer) noexcept;
 * result_type operator () () noexcept;
 * static constexpr result_type min() noexcept;
 * static constexpr result_type max() noexcept;
 *
 * ---- ---- ---- ---- ---- ---- ---- ----
 *
 * detail::basic_random_engine<x, y>
 * x = UIntType
 * y = security strength
 */

using random_engine_128 = detail::basic_random_engine<std::uint64_t, 128>;
using random_engine_256 = detail::basic_random_engine<std::uint64_t, 256>;

/* Interface:
 * static constexpr std::size_t security_strength;
 * static constexpr std::size_t capacity;
 *
 * basic_authenticated_cipher(cmemory_view key) noexcept;
 *
 * void operator () (
 *     cmemory_view header,
 *     memory_view buffer,
 *     cmemory_view body,
 *     memory_view tag) noexcept;
 *
 * ---- ---- ---- ---- ---- ---- ---- ----
 *
 * detail::basic_authenticated_cipher<x, y>
 * x = security strength
 * y = mode (encrypt/decrypt)
 */

using authenticated_encrypter_128 =
	detail::basic_authenticated_cipher<128, detail::cipher_mode::encrypt>;

using authenticated_decrypter_128 =
	detail::basic_authenticated_cipher<128, detail::cipher_mode::decrypt>;

using authenticated_encrypter_256 =
	detail::basic_authenticated_cipher<256, detail::cipher_mode::encrypt>;

using authenticated_decrypter_256 =
	detail::basic_authenticated_cipher<256, detail::cipher_mode::decrypt>;

} // namespace experimental
} // namespace keccak

#endif
