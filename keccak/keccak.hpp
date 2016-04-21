#pragma once

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

	typedef detail::basic_hasher<112, 224, 2> sha3_244_hasher;
	typedef detail::basic_hasher<128, 256, 2> sha3_256_hasher;
	typedef detail::basic_hasher<192, 384, 2> sha3_384_hasher;
	typedef detail::basic_hasher<256, 512, 2> sha3_512_hasher;

	typedef detail::basic_hasher<112, 112, 15> shake112_hasher;
	typedef detail::basic_hasher<128, 128, 15> shake128_hasher;
	typedef detail::basic_hasher<192, 192, 15> shake192_hasher;
	typedef detail::basic_hasher<256, 256, 15> shake256_hasher;

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

	typedef detail::basic_authenticated_cipher<128, detail::cipher_mode::encrypt> authenticated_encrypter_128;
	typedef detail::basic_authenticated_cipher<128, detail::cipher_mode::decrypt> authenticated_decrypter_128;
	typedef detail::basic_authenticated_cipher<256, detail::cipher_mode::encrypt> authenticated_encrypter_256;
	typedef detail::basic_authenticated_cipher<256, detail::cipher_mode::encrypt> authenticated_decrypter_256;

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

	typedef detail::basic_random_engine<std::uint64_t, 128> random_engine_128;
	typedef detail::basic_random_engine<std::uint64_t, 256> random_engine_256;
}
