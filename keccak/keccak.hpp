/* 
 * Copyright (c) 2016 - 2017 cooky451
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

#ifndef KECCAK_49206562
#define KECCAK_49206562

#include <array>
#include <cstdint>
#include <limits>

#include "keccak_detail.hpp"

namespace keccak
{
	/* Interface: 
	 * static constexpr std::size_t collision_resistance;
	 * static constexpr std::size_t preimage_resistance;
	 * static constexpr std::size_t capacity;
	 * static constexpr std::size_t hash_size;
	 * typedef std::array<std::uint8_t, hash_size> hash_type;
	 * 
	 * basic_hasher();
	 * basic_hasher(const void* data, std::size_t size);
	 * void update(const void* data, std::size_t size);
	 * void finish(void* buf, std::size_t size);
	 * hash_type finish();
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
	 *     auto hash = shake128_hasher(data, size).finish();
	 */

	using sha3_244_hasher = detail::basic_hasher<112, 224, 2>;
	using sha3_256_hasher = detail::basic_hasher<128, 256, 2>;
	using sha3_384_hasher = detail::basic_hasher<192, 384, 2>;
	using sha3_512_hasher = detail::basic_hasher<256, 512, 2>;

	using shake112_hasher = detail::basic_hasher<112, 112, 15>;
	using shake128_hasher = detail::basic_hasher<128, 128, 15>;
	using shake192_hasher = detail::basic_hasher<192, 192, 15>;
	using shake256_hasher = detail::basic_hasher<256, 256, 15>;

	/* Interface: 
	 * static constexpr std::size_t security_strength;
	 * static constexpr std::size_t capacity;
	 * 
	 * basic_authenticated_cipher(const void* key, std::size_t key_size);
	 * void operator () (const void* header, std::size_t header_size,
	 * 		void* buffer, const void* body, std::size_t body_and_buffer_size,
	 * 		void* tag, std::size_t tag_size);
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

	/* Interface: 
	 * typedef UIntType result_type;
	 * static constexpr std::size_t state_size;
	 * static constexpr std::size_t security_strength;
	 * static constexpr std::size_t capacity;
	 * 
	 * basic_random_engine(const void* seed, std::size_t size);
	 * void reseed(const void* seed, std::size_t size);
	 * void operator () (void* buffer, std::size_t size);
	 * result_type operator () ();
	 * static constexpr result_type min();
	 * static constexpr result_type max();
	 * 
	 * ---- ---- ---- ---- ---- ---- ---- ---- 
	 * 
	 * detail::basic_random_engine<x, y>
	 * x = UIntType
	 * y = security strength
	 */

	using random_engine_128 = detail::basic_random_engine<std::uint64_t, 128>;
	using random_engine_256 = detail::basic_random_engine<std::uint64_t, 256>;
}

#endif
