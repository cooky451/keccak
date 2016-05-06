#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <array>
#include <limits>

namespace keccak
{
	namespace detail
	{
		// Helper functions

		constexpr unsigned msb_pos(unsigned long long value, unsigned result = 0)
		{
			return value <= 1 ? result : msb_pos(value / 2, result + 1);
		}

		template <typename Word>
		constexpr Word shr(Word w, unsigned amount)
		{
			return w >> amount;
		}

		template <typename Word>
		constexpr Word shl(Word w, unsigned amount)
		{
			return w << amount;
		}

		template <typename Word>
		constexpr Word ror(Word w, unsigned amount)
		{
			return shr(w, amount) | shl(w, std::numeric_limits<Word>::digits - amount);
		}

		template <typename Word>
		constexpr Word rol(Word w, unsigned amount)
		{
			return shl(w, amount) | shr(w, std::numeric_limits<Word>::digits - amount);
		}

		void memory_xor(void* dest, const void* src0, const void* src1, std::size_t size)
		{
			auto d0 = static_cast<std::uint8_t*>(dest);
			auto s0 = static_cast<const std::uint8_t*>(src0);
			auto s1 = static_cast<const std::uint8_t*>(src1);

			// Generates perfect SSE code. Don't iterate over pointers!
			for (std::size_t i = 0; i < size; ++i)
			{
				d0[i] = s0[i] ^ s1[i];
			}
		}

		void memory_xor(void* dest, const void* src, std::size_t size)
		{
			auto d0 = static_cast<std::uint8_t*>(dest);
			auto s0 = static_cast<const std::uint8_t*>(src);

			// Generates perfect SSE code. Don't iterate over pointers!
			for (std::size_t i = 0; i < size; ++i)
			{
				d0[i] ^= s0[i];
			}
		}

		void advance_region(std::size_t)
		{}

		template <typename... Args>
		void advance_region(std::size_t amount, void*& ptr, Args&... args);

		template <typename... Args>
		void advance_region(std::size_t amount, const void*& ptr, Args&... args)
		{
			ptr = static_cast<const std::uint8_t*>(ptr) + amount;
			advance_region(amount, args...);
		}

		template <typename... Args>
		void advance_region(std::size_t amount, void*& ptr, Args&... args)
		{
			ptr = static_cast<std::uint8_t*>(ptr) + amount;
			advance_region(amount, args...);
		}

		template <typename... Args>
		void advance_region(std::size_t amount, std::size_t& size, Args&... args)
		{
			size -= amount;
			advance_region(amount, args...);
		}

		// Base types and constants

		typedef std::uint64_t lane_type;
		typedef std::array<std::array<std::uint64_t, 5>, 5> state_type;

		static_assert(sizeof(state_type) == sizeof(lane_type) * 25, "std::array has padding.");
		static_assert(std::is_same<unsigned char, std::uint8_t>::value
			|| std::is_same<char, std::uint8_t>::value, 
			"std::uint8_t isn't char-type and therefore not exempt from strict aliasing.");

		constexpr std::size_t n_rounds = 12 + 2 * msb_pos(std::numeric_limits<lane_type>::digits);

		enum class cipher_mode : std::uint8_t
		{
			encrypt,
			decrypt,
		};

		constexpr std::array<std::array<unsigned, 5>, 5> rotation_offsets =
		{
			0, 1, 62, 28, 27,
			36, 44, 6, 55, 20,
			3, 10, 43, 25, 39,
			41, 45, 15, 21, 8,
			18, 2, 61, 56, 14,
		};

		constexpr std::array<std::uint64_t, n_rounds> round_constants =
		{
			0x0000000000000001ull,
			0x0000000000008082ull,
			0x800000000000808Aull,
			0x8000000080008000ull,
			0x000000000000808Bull,
			0x0000000080000001ull,
			0x8000000080008081ull,
			0x8000000000008009ull,
			0x000000000000008Aull,
			0x0000000000000088ull,
			0x0000000080008009ull,
			0x000000008000000Aull,
			0x000000008000808Bull,
			0x800000000000008Bull,
			0x8000000000008089ull,
			0x8000000000008003ull,
			0x8000000000008002ull,
			0x8000000000000080ull,
			0x000000000000800Aull,
			0x800000008000000Aull,
			0x8000000080008081ull,
			0x8000000000008080ull,
			0x0000000080000001ull,
			0x8000000080008008ull,
		};

		// Keccak round function

		void round(state_type& s, lane_type round_constant)
		{
			auto c0 = s[0][0] ^ s[1][0] ^ s[2][0] ^ s[3][0] ^ s[4][0];
			auto c1 = s[0][1] ^ s[1][1] ^ s[2][1] ^ s[3][1] ^ s[4][1];
			auto c2 = s[0][2] ^ s[1][2] ^ s[2][2] ^ s[3][2] ^ s[4][2];
			auto c3 = s[0][3] ^ s[1][3] ^ s[2][3] ^ s[3][3] ^ s[4][3];
			auto c4 = s[0][4] ^ s[1][4] ^ s[2][4] ^ s[3][4] ^ s[4][4];

			auto d0 = c4 ^ rol(c1, 1);
			auto d1 = c0 ^ rol(c2, 1);
			auto d2 = c1 ^ rol(c3, 1);
			auto d3 = c2 ^ rol(c4, 1);
			auto d4 = c3 ^ rol(c0, 1);

			s[0][0] ^= d0;
			s[0][1] ^= d1;
			s[0][2] ^= d2;
			s[0][3] ^= d3;
			s[0][4] ^= d4;
			s[1][0] ^= d0;
			s[1][1] ^= d1;
			s[1][2] ^= d2;
			s[1][3] ^= d3;
			s[1][4] ^= d4;
			s[2][0] ^= d0;
			s[2][1] ^= d1;
			s[2][2] ^= d2;
			s[2][3] ^= d3;
			s[2][4] ^= d4;
			s[3][0] ^= d0;
			s[3][1] ^= d1;
			s[3][2] ^= d2;
			s[3][3] ^= d3;
			s[3][4] ^= d4;
			s[4][0] ^= d0;
			s[4][1] ^= d1;
			s[4][2] ^= d2;
			s[4][3] ^= d3;
			s[4][4] ^= d4;

			auto s00 = rol(s[0][0], rotation_offsets[0][0]);
			auto s20 = rol(s[0][1], rotation_offsets[0][1]);
			auto s40 = rol(s[0][2], rotation_offsets[0][2]);
			auto s10 = rol(s[0][3], rotation_offsets[0][3]);
			auto s30 = rol(s[0][4], rotation_offsets[0][4]);
			auto s31 = rol(s[1][0], rotation_offsets[1][0]);
			auto s01 = rol(s[1][1], rotation_offsets[1][1]);
			auto s21 = rol(s[1][2], rotation_offsets[1][2]);
			auto s41 = rol(s[1][3], rotation_offsets[1][3]);
			auto s11 = rol(s[1][4], rotation_offsets[1][4]);
			auto s12 = rol(s[2][0], rotation_offsets[2][0]);
			auto s32 = rol(s[2][1], rotation_offsets[2][1]);
			auto s02 = rol(s[2][2], rotation_offsets[2][2]);
			auto s22 = rol(s[2][3], rotation_offsets[2][3]);
			auto s42 = rol(s[2][4], rotation_offsets[2][4]);
			auto s43 = rol(s[3][0], rotation_offsets[3][0]);
			auto s13 = rol(s[3][1], rotation_offsets[3][1]);
			auto s33 = rol(s[3][2], rotation_offsets[3][2]);
			auto s03 = rol(s[3][3], rotation_offsets[3][3]);
			auto s23 = rol(s[3][4], rotation_offsets[3][4]);
			auto s24 = rol(s[4][0], rotation_offsets[4][0]);
			auto s44 = rol(s[4][1], rotation_offsets[4][1]);
			auto s14 = rol(s[4][2], rotation_offsets[4][2]);
			auto s34 = rol(s[4][3], rotation_offsets[4][3]);
			auto s04 = rol(s[4][4], rotation_offsets[4][4]);

			s[0][0] = s00 ^ (~s01 & s02);
			s[0][1] = s01 ^ (~s02 & s03);
			s[0][2] = s02 ^ (~s03 & s04);
			s[0][3] = s03 ^ (~s04 & s00);
			s[0][4] = s04 ^ (~s00 & s01);
			s[1][0] = s10 ^ (~s11 & s12);
			s[1][1] = s11 ^ (~s12 & s13);
			s[1][2] = s12 ^ (~s13 & s14);
			s[1][3] = s13 ^ (~s14 & s10);
			s[1][4] = s14 ^ (~s10 & s11);
			s[2][0] = s20 ^ (~s21 & s22);
			s[2][1] = s21 ^ (~s22 & s23);
			s[2][2] = s22 ^ (~s23 & s24);
			s[2][3] = s23 ^ (~s24 & s20);
			s[2][4] = s24 ^ (~s20 & s21);
			s[3][0] = s30 ^ (~s31 & s32);
			s[3][1] = s31 ^ (~s32 & s33);
			s[3][2] = s32 ^ (~s33 & s34);
			s[3][3] = s33 ^ (~s34 & s30);
			s[3][4] = s34 ^ (~s30 & s31);
			s[4][0] = s40 ^ (~s41 & s42);
			s[4][1] = s41 ^ (~s42 & s43);
			s[4][2] = s42 ^ (~s43 & s44);
			s[4][3] = s43 ^ (~s44 & s40);
			s[4][4] = s44 ^ (~s40 & s41);

			s[0][0] ^= round_constant;
		}

		void keccak_f(state_type& s)
		{
			for (std::size_t i = 0; i < round_constants.size(); ++i)
			{
				round(s, round_constants[i]);
			}
		}

		class capacity
		{
			std::uint8_t _n_bytes;

		public:
			template <std::size_t NBits>
			static constexpr capacity make()
			{
				return capacity(static_cast<std::uint8_t>(NBits / 8));

				static_assert(NBits % width() == 0, "Rate / width combination not supported.");
				static_assert(NBits < 25 * width(), "Capacity too high.");
				static_assert(sizeof(state_type) < std::numeric_limits<std::uint8_t>::max(), "State too wide.");
			}

			constexpr static std::size_t width()
			{
				return std::numeric_limits<lane_type>::digits;
			}

			constexpr static std::size_t byte_width()
			{
				return sizeof(lane_type);
			}

			constexpr  std::size_t n_bits() const
			{
				return n_bytes() * 8;
			}

			constexpr std::size_t n_bytes() const
			{
				return _n_bytes;
			}

			constexpr std::size_t rate() const
			{
				return byte_rate() * 8;
			}

			constexpr std::size_t byte_rate() const
			{
				return sizeof(state_type) - n_bytes();
			}

			constexpr std::size_t n_elements() const
			{
				return rate() / width();
			}

		private:
			explicit constexpr capacity(std::uint8_t n_bytes)
				: _n_bytes(n_bytes)
			{}
		};

		class domain
		{
			std::uint8_t _domain;

		public:
			template <std::uint8_t Value>
			static constexpr domain make()
			{
				return domain(Value);

				static_assert(domain_size(Value) <= 6, "Domain value too high.");
			}

			constexpr std::uint8_t value() const
			{
				return _domain;
			}

			constexpr std::uint8_t size() const
			{
				return domain_size(value());
			}

		private:
			explicit constexpr domain(std::uint8_t value)
				: _domain(value)
			{}

			static constexpr std::uint8_t domain_size(std::uint8_t value)
			{
				return value == 0 ? 0 : static_cast<std::uint8_t>(1 + msb_pos(value));
			}
		};

		class sponge
		{
			state_type _state = {};
			std::size_t _bytes_processed = 0;
			capacity _capacity;
			bool _squeezing = false;

		public:
			constexpr sponge(capacity cap)
				: _capacity(cap)
			{}

			constexpr std::size_t byte_rate() const
			{
				return _capacity.byte_rate();
			}

			const std::uint8_t* state_bytes() const
			{
				return reinterpret_cast<const std::uint8_t*>(_state[0].data());
			}

			std::uint8_t* state_bytes()
			{
				return reinterpret_cast<std::uint8_t*>(_state[0].data());
			}

			void absorb(const void* data, std::size_t size, domain dom)
			{
				if (_squeezing)
				{
					_squeezing = false;
					pad(dom);
					transform();
				}

				while (size > 0)
				{
					const auto chunk_size = std::min(size, byte_rate() - _bytes_processed);
					memory_xor(state_bytes() + _bytes_processed, data, chunk_size);

					_bytes_processed += chunk_size;
					advance_region(chunk_size, size, data);

					if (_bytes_processed == byte_rate())
					{
						transform();
					}
				}
			}

			void squeeze(void* buffer, std::size_t size, domain dom)
			{
				if (!_squeezing)
				{
					_squeezing = true;
					pad(dom);
					transform();
				}

				while (size > 0)
				{
					if (_bytes_processed == byte_rate())
					{
						transform();
					}

					const auto chunk_size = std::min(size, byte_rate() - _bytes_processed);
					std::memcpy(buffer, state_bytes() + _bytes_processed, chunk_size);

					_bytes_processed += chunk_size;
					advance_region(chunk_size, size, buffer);
				}
			}

		private:
			void pad(domain dom)
			{
				state_bytes()[_bytes_processed] ^= (1u << dom.size()) | dom.value();
				state_bytes()[_capacity.byte_rate() - 1] ^= 128u;
			}

			void transform()
			{
				keccak_f(_state);
				_bytes_processed = 0;
			}
		};

		class sponge_duplex
		{
			state_type _state = {};
			capacity _capacity;

		public:
			constexpr sponge_duplex(capacity cap)
				: _capacity(cap)
			{}

			constexpr std::size_t byte_rate() const
			{
				return _capacity.byte_rate();
			}

			const std::uint8_t* state_bytes() const
			{
				return reinterpret_cast<const std::uint8_t*>(_state[0].data());
			}

			std::uint8_t* state_bytes()
			{
				return reinterpret_cast<std::uint8_t*>(_state[0].data());
			}

			void absorb_transform(const void* data, std::size_t data_size, domain dom)
			{
				// assert(_capacity.byte_rate() >= buffer_size);
				// assert(_capacity.byte_rate() - 1 >= data_size);

				memory_xor(state_bytes(), data, data_size);

				state_bytes()[data_size] ^= (1u << dom.size()) | dom.value();
				state_bytes()[_capacity.byte_rate() - 1] ^= 128u;

				keccak_f(_state);
			}

			void transform()
			{
				keccak_f(_state);
			}
		};

		class sponge_wrap
		{
			sponge_duplex _sponge;

		public:
			sponge_wrap(capacity cap, const void* key, std::size_t size)
				: _sponge(cap)
			{
				const auto duplex_rate = _sponge.byte_rate() - 1;

				while (size > duplex_rate)
				{
					_sponge.absorb_transform(key, size, domain::make<1>());
					advance_region(duplex_rate, size, key);
				}

				_sponge.absorb_transform(key, size, domain::make<0>());
			}

			void wrap(const void* header, std::size_t header_size,
				void* buffer, const void* body, std::size_t body_and_buffer_size,
				void* tag, std::size_t tag_size)
			{
				wrap_impl(header, header_size, buffer, body, body_and_buffer_size, tag, tag_size, body);
			}

			void unwrap(const void* header, std::size_t header_size,
				void* buffer, const void* body, std::size_t body_and_buffer_size,
				void* tag, std::size_t tag_size)
			{
				wrap_impl(header, header_size, buffer, body, body_and_buffer_size, tag, tag_size, buffer);
			}

		private:
			void wrap_impl(const void* header, std::size_t header_size,
				void* buffer, const void* body, std::size_t body_and_buffer_size,
				void* tag, std::size_t tag_size, const void* duplex_source)
			{
				// We need to leave 1 byte for padding, as each block gets
				// padded, unlike in the normal sponge mode.

				const auto duplex_rate = _sponge.byte_rate() - 1;

				while (header_size > duplex_rate)
				{
					_sponge.absorb_transform(header, header_size, domain::make<0>());
					advance_region(duplex_rate, header_size, header);
				}

				_sponge.absorb_transform(header, header_size, domain::make<1>());

				while (body_and_buffer_size > duplex_rate)
				{
					memory_xor(buffer, body, _sponge.state_bytes(), duplex_rate);
					_sponge.absorb_transform(duplex_source, duplex_rate, domain::make<0>());
					advance_region(duplex_rate, body_and_buffer_size, buffer, body);
				}

				memory_xor(buffer, body, _sponge.state_bytes(), body_and_buffer_size);
				_sponge.absorb_transform(duplex_source, body_and_buffer_size, domain::make<0>());

				while (tag_size > _sponge.byte_rate()) // We can use the full rate as output.
				{
					std::memcpy(tag, _sponge.state_bytes(), _sponge.byte_rate());
					advance_region(_sponge.byte_rate(), tag_size, tag);
					_sponge.absorb_transform(nullptr, 0, domain::make<0>());
				}

				std::memcpy(tag, _sponge.state_bytes(), tag_size);
			}
		};

		template <std::uint8_t Domain>
		class sponge_prg
		{
			state_type _state = {};
			std::size_t _bytes_processed = 0;
			capacity _capacity;
			bool _fetching = false;

		public:
			constexpr sponge_prg(capacity cap)
				: _capacity(cap)
			{}

			void feed(const void* data, std::size_t size)
			{
				if (_fetching)
				{
					_fetching = false;
					pad_and_transform();
				}

				while (size > 0)
				{
					const auto chunk_size = std::min(size, _capacity.byte_rate() - 1 - _bytes_processed);
					memory_xor(state_bytes() + _bytes_processed, data, chunk_size);

					_bytes_processed += chunk_size;
					advance_region(chunk_size, size, data);

					if (_bytes_processed == _capacity.byte_rate() - 1)
					{
						pad_and_transform();
					}
				}
			}

			void fetch(void* buffer, std::size_t size)
			{
				if (!_fetching)
				{
					_fetching = true;
					pad_and_transform();
				}

				while (size > 0)
				{
					const auto chunk_size = std::min(size, _capacity.byte_rate() - 1 - _bytes_processed);
					std::memcpy(buffer, state_bytes() + _bytes_processed, chunk_size);

					_bytes_processed += chunk_size;
					advance_region(chunk_size, size, buffer);

					if (_bytes_processed == _capacity.byte_rate() - 1)
					{
						pad_and_transform();
					}
				}
			}

			void pad_and_transform()
			{
				static constexpr auto dom = domain::make<Domain>();

				state_bytes()[_bytes_processed] ^= (1u << dom.size()) | dom.value();
				state_bytes()[_capacity.byte_rate() - 1] ^= 128u;

				_bytes_processed = 0;

				keccak_f(_state);
			}

			std::uint8_t* state_bytes()
			{
				return reinterpret_cast<std::uint8_t*>(_state[0].data());
			}
		};

		template <std::size_t CollisionResistance, std::size_t PreimageResistance, std::uint8_t Domain>
		class basic_hasher
		{
		public:
			static constexpr std::size_t collision_resistance = CollisionResistance;
			static constexpr std::size_t preimage_resistance = PreimageResistance;

			static constexpr std::size_t capacity = std::max(collision_resistance * 2, preimage_resistance * 2);
			static constexpr std::size_t hash_size = std::max(collision_resistance * 2 / 8, preimage_resistance / 8);

			typedef std::array<std::uint8_t, hash_size> hash_type;

		private:
			sponge _sponge;

		public:
			constexpr basic_hasher()
				: _sponge(capacity::make<capacity>())
			{}

			basic_hasher(const void* data, std::size_t size)
				: basic_hasher()
			{
				update(data, size);
			}

			void update(const void* data, std::size_t size)
			{
				_sponge.absorb(data, size, domain::make<Domain>());
			}

			void finish(void* buf, std::size_t size)
			{
				_sponge.squeeze(buf, size, domain::make<Domain>());
				*this = basic_hasher();
			}

			hash_type finish()
			{
				hash_type hash;
				finish(hash.data(), hash.size());
				return hash;
			}
		};

		template <std::size_t SecurityStrength, cipher_mode Mode>
		class basic_authenticated_cipher
		{
		public:
			static constexpr std::size_t security_strength = SecurityStrength;
			static constexpr std::size_t capacity = security_strength * 2;

		private:
			sponge_wrap _wrapper;

		public:
			basic_authenticated_cipher(const void* key, std::size_t key_size)
				: _wrapper(capacity::make<capacity>(), key, key_size)
			{}

			void operator () (const void* header, std::size_t header_size,
				void* buffer, const void* body, std::size_t body_and_buffer_size,
				void* tag, std::size_t tag_size)
			{
				switch (Mode)
				{
				default:
					// assert(false);
					break;
				case cipher_mode::encrypt:
					_wrapper.wrap(header, header_size, buffer, body, body_and_buffer_size, tag, tag_size);
					break;
				case cipher_mode::decrypt:
					_wrapper.unwrap(header, header_size, buffer, body, body_and_buffer_size, tag, tag_size);
					break;
				}
			}
		};

		template <typename UIntType, std::size_t SecurityStrength>
		class basic_random_engine
		{
		public:
			typedef UIntType result_type;

			static constexpr std::size_t state_size = sizeof(state_type);
			static constexpr std::size_t security_strength = SecurityStrength;
			static constexpr std::size_t capacity = security_strength * 2;

		private:
			sponge_prg<21> _prg;

		public:
			basic_random_engine(const void* seed, std::size_t size)
				: _prg(capacity::make<capacity>())
			{
				reseed(seed, size);
			}

			void reseed(const void* seed, std::size_t size)
			{
				_prg.feed(seed, size);
			}

			void operator () (void* buffer, std::size_t size)
			{
				_prg.fetch(buffer, size);
			}

			result_type operator () ()
			{
				result_type r;
				(*this)(&r, sizeof r);
				return r;
			}

			static constexpr result_type min()
			{
				return std::numeric_limits<result_type>::min();
			}

			static constexpr result_type max()
			{
				return std::numeric_limits<result_type>::max();
			}
		};
	}
}
