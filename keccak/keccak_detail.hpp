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

		void memory_xor(void* dst, const void* src0, const void* src1, std::size_t size)
		{
			auto d0 = static_cast<std::uint8_t*>(dst);
			auto s0 = static_cast<const std::uint8_t*>(src0);
			auto s1 = static_cast<const std::uint8_t*>(src1);

			for (std::size_t i = 0; i < size; ++i)
			{
				d0[i] = s0[i] ^ s1[i];
			}
		}

		void memory_xor(void* dst, const void* src, std::size_t size)
		{
			auto dstp = static_cast<std::uint8_t*>(dst);
			auto srcp = static_cast<const std::uint8_t*>(src);

			for (std::size_t i = 0; i < size; ++i)
			{
				dstp[i] ^= srcp[i];
			}
		}

		template <std::size_t Size>
		void memory_xor(void* dst, const void* src0, const void* src1)
		{
			auto d0 = static_cast<std::uint8_t*>(dst);
			auto s0 = static_cast<const std::uint8_t*>(src0);
			auto s1 = static_cast<const std::uint8_t*>(src1);

			for (std::size_t i = 0; i < Size; ++i)
			{
				d0[i] = s0[i] ^ s1[i];
			}
		}

		template <std::size_t Size>
		void memory_xor(void* dst, const void* src)
		{
			auto dstp = static_cast<std::uint8_t*>(dst);
			auto srcp = static_cast<const std::uint8_t*>(src);

			for (std::size_t i = 0; i < Size; ++i)
			{
				dstp[i] ^= srcp[i];
			}
		}

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

		enum class sponge_mode : std::uint8_t
		{
			normal, 
			duplex, 
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
			sponge_mode _mode;
			bool _squeezing = false;

		public:
			constexpr sponge(capacity cap, sponge_mode mode)
				: _capacity(cap)
				, _mode(mode)
			{}

			constexpr bool is_duplex() const
			{
				return _mode == sponge_mode::duplex;
			}

			constexpr std::size_t byte_rate() const
			{
				return _capacity.byte_rate() - is_duplex();
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
					transform_state(true, dom);
				}

				if (_bytes_processed == 0 && size == 167)
				{
					memory_xor<167>(state_bytes() + _bytes_processed, data);
					transform_state(is_duplex(), dom);
					return;
				}

				while (size > 0)
				{
					const auto chunk_size = std::min(size, byte_rate() - _bytes_processed);
					memory_xor(state_bytes() + _bytes_processed, data, chunk_size);
					_bytes_processed += chunk_size;
					size -= chunk_size;
					data = static_cast<const std::uint8_t*>(data) + chunk_size;

					if (_bytes_processed == byte_rate())
					{
						transform_state(is_duplex(), dom);
					}

				}
			}

			void squeeze(void* buffer, std::size_t size, domain dom)
			{
				if (!_squeezing)
				{
					_squeezing = true;

					if (!is_duplex() || _bytes_processed != 0)
					{
						transform_state(true, dom);
					}
				}

				while (size > 0)
				{
					if (_bytes_processed == byte_rate())
					{
						transform_state(is_duplex(), dom);
					}

					const auto chunk_size = std::min(size, byte_rate() - _bytes_processed);
					std::memcpy(buffer, state_bytes() + _bytes_processed, chunk_size);

					_bytes_processed += chunk_size;
					size -= chunk_size;
					buffer = static_cast<std::uint8_t*>(buffer) + chunk_size;
				}
			}

			void transform_state(bool pad_message, domain dom)
			{
				if (pad_message)
				{
					state_bytes()[_bytes_processed] ^= (1u << dom.size()) | dom.value();
					state_bytes()[_capacity.byte_rate() - 1] ^= 128u;
				}
				
				keccak_f(_state);
				_bytes_processed = 0;
			}
		};

		class sponge_wrap
		{
			static constexpr domain domain_zero = domain::make<0>();
			static constexpr domain domain_one = domain::make<1>();

			sponge _sponge;

		public:
			sponge_wrap(capacity cap, const void* key, std::size_t size)
				: _sponge(cap, sponge_mode::duplex)
			{
				auto key_rest = static_cast<const std::uint8_t*>(key) + size / _sponge.byte_rate();
				_sponge.absorb(key, size / _sponge.byte_rate(), domain_zero);
				_sponge.absorb(key_rest, size % _sponge.byte_rate(), domain_one);
				_sponge.transform_state(true, domain_one);
			}

			void operator () (const void* header, std::size_t header_size,
				void* buffer, const void* body, std::size_t body_and_buffer_size,
				void* tag, std::size_t tag_size, cipher_mode mode)
			{
				const auto& duplex_source = mode == cipher_mode::encrypt ? body : buffer;

				auto header_rest = static_cast<const std::uint8_t*>(header) + header_size / _sponge.byte_rate();
				_sponge.absorb(header, header_size / _sponge.byte_rate(), domain_zero);
				_sponge.absorb(header_rest, header_size % _sponge.byte_rate(), domain_one);

				while (body_and_buffer_size > _sponge.byte_rate())
				{
					memory_xor(buffer, body, _sponge.state_bytes(), _sponge.byte_rate());
					_sponge.absorb(duplex_source, _sponge.byte_rate(), domain_one);

					buffer = static_cast<std::uint8_t*>(buffer) + _sponge.byte_rate();
					body = static_cast<const std::uint8_t*>(body) + _sponge.byte_rate();
					body_and_buffer_size -= _sponge.byte_rate();
				}

				memory_xor(buffer, body, _sponge.state_bytes(), body_and_buffer_size);
				_sponge.absorb(duplex_source, body_and_buffer_size, domain_zero);

				_sponge.squeeze(tag, tag_size, domain_one);
			}
		};

		constexpr domain sponge_wrap::domain_one;
		constexpr domain sponge_wrap::domain_zero;

		template <std::uint8_t Domain>
		class sponge_prg
		{
			sponge _sponge;

		public:
			constexpr sponge_prg(capacity cap)
				: _sponge(cap, sponge_mode::duplex)
			{}

			void feed(const void* data, std::size_t size)
			{
				_sponge.absorb(data, size, domain::make<Domain>());
			}

			void fetch(void* buffer, std::size_t size)
			{
				_sponge.squeeze(buffer, size, domain::make<Domain>());
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

			static constexpr domain dom = domain::make<Domain>();

			typedef std::array<std::uint8_t, hash_size> hash_type;

		private:
			sponge _sponge;

		public:
			constexpr basic_hasher()
				: _sponge(capacity::make<capacity>(), sponge_mode::normal)
			{}

			basic_hasher(const void* data, std::size_t size)
				: basic_hasher()
			{
				update(data, size);
			}

			void update(const void* data, std::size_t size)
			{
				_sponge.absorb(data, size, dom);
			}

			void finish(void* buf, std::size_t size)
			{
				_sponge.squeeze(buf, size, dom);
				*this = basic_hasher();
			}

			hash_type finish()
			{
				hash_type hash;
				finish(hash.data(), hash.size());
				return hash;
			}
		};

		template <std::size_t CollisionResistance, std::size_t PreimageResistance, std::uint8_t Domain>
		constexpr domain basic_hasher<CollisionResistance, PreimageResistance, Domain>::dom;

		template <std::size_t SecurityStrength, cipher_mode Mode>
		class basic_authenticated_cipher
		{
		public:
			static constexpr std::size_t security_strength = SecurityStrength;
			static constexpr std::size_t capacity = security_strength * 2;

		private:
			sponge_wrap _wrap;

		public:
			basic_authenticated_cipher(const void* key, std::size_t key_size)
				: _wrap(capacity::make<capacity>(), key, key_size)
			{}

			void operator () (const void* header, std::size_t header_size,
				void* buffer, const void* body, std::size_t body_and_buffer_size,
				void* tag, std::size_t tag_size)
			{
				_wrap(header, header_size, buffer, body, body_and_buffer_size, tag, tag_size, Mode);
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

//class sponge_prg
//{
//	state_type _state = {};
//	std::size_t _bytes_processed = 0;
//	capacity _capacity;
//	domain _domain;
//	bool _fetching = false;

//public:
//	constexpr sponge_prg(capacity cap, domain dom)
//		: _capacity(cap)
//		, _domain(dom)
//	{}

//	void feed(const void* data, std::size_t size)
//	{
//		if (_fetching)
//		{
//			_fetching = false;
//			pad_and_transform();
//		}

//		while (size > 0)
//		{
//			const auto chunk_size = std::min(size, _capacity.byte_rate() - 1 - _bytes_processed);
//			memory_xor(state_bytes() + _bytes_processed, data, chunk_size);

//			_bytes_processed += chunk_size;
//			size -= chunk_size;
//			data = static_cast<const std::uint8_t*>(data) + chunk_size;

//			if (_bytes_processed == _capacity.byte_rate())
//			{
//				pad_and_transform();
//			}
//		}
//	}

//	void fetch(void* buffer, std::size_t size)
//	{
//		if (!_fetching)
//		{
//			_fetching = true;
//			pad_and_transform();
//		}

//		while (size > 0)
//		{
//			const auto chunk_size = std::min(size, _capacity.byte_rate() - 1 - _bytes_processed);
//			std::memcpy(buffer, state_bytes() + _bytes_processed, chunk_size);

//			_bytes_processed += chunk_size;
//			size -= chunk_size;
//			buffer = static_cast<std::uint8_t*>(buffer) + chunk_size;

//			if (_bytes_processed == _capacity.byte_rate() - 1)
//			{
//				pad_and_transform();
//			}
//		}
//	}

//	void pad_and_transform()
//	{
//		state_bytes()[_bytes_processed] ^= (1u << _domain.size()) | _domain.value();
//		state_bytes()[_capacity.byte_rate() - 1] ^= 128u;

//		_bytes_processed = 0;

//		keccak_f(_state);
//	}

//	std::uint8_t* state_bytes()
//	{
//		return reinterpret_cast<std::uint8_t*>(_state[0].data());
//	}
//};

//class sponge_wrap
//{
//	static constexpr domain domain_zero = domain::make<0>();
//	static constexpr domain domain_one = domain::make<1>();

//	sponge _sponge;

//public:
//	sponge_wrap(capacity cap, const void* key, std::size_t size)
//		: _sponge(cap, sponge_mode::duplex)
//	{
//		const auto byte_rate = _capacity.byte_rate() - 1;

//		while (size > byte_rate)
//		{
//			absorb_and_transform(data, byte_rate, domain_zero);

//			data = static_cast<const std::uint8_t*>(data) + byte_rate;
//			size -= byte_rate;
//		}

//		absorb_and_transform(data, size, domain_one);
//	}

//	void operator () (const void* header, std::size_t header_size,
//		void* buffer, const void* body, std::size_t body_and_buffer_size,
//		void* tag, std::size_t tag_size, cipher_mode mode)
//	{
//		const auto byte_rate = _capacity.byte_rate() - 1;
//		const auto& duplex_source = mode == cipher_mode::encrypt ? body : buffer;

//		while (header_size > byte_rate)
//		{
//			absorb_and_transform(header, byte_rate, domain_zero);

//			header = static_cast<const std::uint8_t*>(header) + byte_rate;
//			header_size -= byte_rate;
//		}

//		absorb_and_transform(header, header_size, domain_one);

//		while (body_and_buffer_size > byte_rate)
//		{
//			memory_xor(buffer, body, state_bytes(), byte_rate);
//			absorb_and_transform(duplex_source, byte_rate, domain_one);

//			buffer = static_cast<std::uint8_t*>(buffer) + byte_rate;
//			body = static_cast<const std::uint8_t*>(body) + byte_rate;
//			body_and_buffer_size -= byte_rate;
//		}

//		memory_xor(buffer, body, state_bytes(), body_and_buffer_size);
//		absorb_and_transform(duplex_source, body_and_buffer_size, domain_zero);

//		while (tag_size > byte_rate)
//		{
//			std::memcpy(tag, state_bytes(), byte_rate);
//			absorb_and_transform(nullptr, 0, domain_one);

//			tag_size -= byte_rate;
//			tag = static_cast<std::uint8_t*>(tag) + byte_rate;
//		}

//		std::memcpy(tag, state_bytes(), tag_size);
//	}

//	void absorb_and_transform(const void* data, std::size_t size, domain dom)
//	{
//		//assert(size < state_type::byte_rate);
//		//assert(bufsize <= state_type::byte_rate);

//		memory_xor(state_bytes(), data, size);
//		
//		state_bytes()[size] ^= (1u << dom.size()) | dom.value();
//		state_bytes()[_capacity.byte_rate() - 1] ^= 128u;

//		keccak_f(_state);
//	}

//	std::uint8_t* state_bytes()
//	{
//		return reinterpret_cast<std::uint8_t*>(_state[0].data());
//	}
//};

//0, 1, 62, 28, 27, 
//36, 44, 6, 55, 20, 
//3, 10, 43, 25, 39, 
//41, 45, 15, 21, 8, 
//18, 2, 61, 56, 14, 

//round(state, round_constants[0]);
//round(state, round_constants[1]);
//round(state, round_constants[2]);
//round(state, round_constants[3]);

//round(state, round_constants[4]);
//round(state, round_constants[5]);
//round(state, round_constants[6]);
//round(state, round_constants[7]);

//round(state, round_constants[8]);
//round(state, round_constants[9]);
//round(state, round_constants[10]);
//round(state, round_constants[11]);

//round(state, round_constants[12]);
//round(state, round_constants[13]);
//round(state, round_constants[14]);
//round(state, round_constants[15]);

//round(state, round_constants[16]);
//round(state, round_constants[17]);
//round(state, round_constants[18]);
//round(state, round_constants[19]);

//round(state, round_constants[20]);
//round(state, round_constants[21]);
//round(state, round_constants[22]);
//round(state, round_constants[23]);

//void round(state_type& s, lane_type round_constant)
//{
//	auto
//		s00 = s[0][0], s01 = s[0][1], s02 = s[0][2], s03 = s[0][3], s04 = s[0][4],
//		s10 = s[1][0], s11 = s[1][1], s12 = s[1][2], s13 = s[1][3], s14 = s[1][4],
//		s20 = s[2][0], s21 = s[2][1], s22 = s[2][2], s23 = s[2][3], s24 = s[2][4],
//		s30 = s[3][0], s31 = s[3][1], s32 = s[3][2], s33 = s[3][3], s34 = s[3][4],
//		s40 = s[4][0], s41 = s[4][1], s42 = s[4][2], s43 = s[4][3], s44 = s[4][4];

//	auto c0 = s00 ^ s10 ^ s20 ^ s30 ^ s40;
//	auto c1 = s01 ^ s11 ^ s21 ^ s31 ^ s41;
//	auto c2 = s02 ^ s12 ^ s22 ^ s32 ^ s42;
//	auto c3 = s03 ^ s13 ^ s23 ^ s33 ^ s43;
//	auto c4 = s04 ^ s14 ^ s24 ^ s34 ^ s44;

//	auto d0 = c4 ^ rol(c1, 1);
//	auto d1 = c0 ^ rol(c2, 1);
//	auto d2 = c1 ^ rol(c3, 1);
//	auto d3 = c2 ^ rol(c4, 1);
//	auto d4 = c3 ^ rol(c0, 1);

//	s00 ^= d0;
//	s01 ^= d1;
//	s02 ^= d2;
//	s03 ^= d3;
//	s04 ^= d4;

//	auto t00 = rol(s00, rotation_offsets[0][0]);
//	auto t20 = rol(s01, rotation_offsets[0][1]);
//	auto t40 = rol(s02, rotation_offsets[0][2]);
//	auto t10 = rol(s03, rotation_offsets[0][3]);
//	auto t30 = rol(s04, rotation_offsets[0][4]);

//	s10 ^= d0;
//	s11 ^= d1;
//	s12 ^= d2;
//	s13 ^= d3;
//	s14 ^= d4;

//	auto t31 = rol(s10, rotation_offsets[1][0]);
//	auto t01 = rol(s11, rotation_offsets[1][1]);
//	auto t21 = rol(s12, rotation_offsets[1][2]);
//	auto t41 = rol(s13, rotation_offsets[1][3]);
//	auto t11 = rol(s14, rotation_offsets[1][4]);

//	s20 ^= d0;
//	s21 ^= d1;
//	s22 ^= d2;
//	s23 ^= d3;
//	s24 ^= d4;

//	auto t12 = rol(s20, rotation_offsets[2][0]);
//	auto t32 = rol(s21, rotation_offsets[2][1]);
//	auto t02 = rol(s22, rotation_offsets[2][2]);
//	auto t22 = rol(s23, rotation_offsets[2][3]);
//	auto t42 = rol(s24, rotation_offsets[2][4]);

//	s30 ^= d0;
//	s31 ^= d1;
//	s32 ^= d2;
//	s33 ^= d3;
//	s34 ^= d4;

//	auto t43 = rol(s30, rotation_offsets[3][0]);
//	auto t13 = rol(s31, rotation_offsets[3][1]);
//	auto t33 = rol(s32, rotation_offsets[3][2]);
//	auto t03 = rol(s33, rotation_offsets[3][3]);
//	auto t23 = rol(s34, rotation_offsets[3][4]);

//	s40 ^= d0;
//	s41 ^= d1;
//	s42 ^= d2;
//	s43 ^= d3;
//	s44 ^= d4;

//	auto t24 = rol(s40, rotation_offsets[4][0]);
//	auto t44 = rol(s41, rotation_offsets[4][1]);
//	auto t14 = rol(s42, rotation_offsets[4][2]);
//	auto t34 = rol(s43, rotation_offsets[4][3]);
//	auto t04 = rol(s44, rotation_offsets[4][4]);

//	// 
//	s[0][0] = t00 ^ (~t01 & t02);
//	s[0][1] = t01 ^ (~t02 & t03);
//	s[0][2] = t02 ^ (~t03 & t04);
//	s[0][3] = t03 ^ (~t04 & t00);
//	s[0][4] = t04 ^ (~t00 & t01);

//	s[1][0] = t10 ^ (~t11 & t12);
//	s[1][1] = t11 ^ (~t12 & t13);
//	s[1][2] = t12 ^ (~t13 & t14);
//	s[1][3] = t13 ^ (~t14 & t10);
//	s[1][4] = t14 ^ (~t10 & t11);

//	s[2][0] = t20 ^ (~t21 & t22);
//	s[2][1] = t21 ^ (~t22 & t23);
//	s[2][2] = t22 ^ (~t23 & t24);
//	s[2][3] = t23 ^ (~t24 & t20);
//	s[2][4] = t24 ^ (~t20 & t21);

//	s[3][0] = t30 ^ (~t31 & t32);
//	s[3][1] = t31 ^ (~t32 & t33);
//	s[3][2] = t32 ^ (~t33 & t34);
//	s[3][3] = t33 ^ (~t34 & t30);
//	s[3][4] = t34 ^ (~t30 & t31);

//	s[4][0] = t40 ^ (~t41 & t42);
//	s[4][1] = t41 ^ (~t42 & t43);
//	s[4][2] = t42 ^ (~t43 & t44);
//	s[4][3] = t43 ^ (~t44 & t40);
//	s[4][4] = t44 ^ (~t40 & t41);

//	s[0][0] ^= round_constant;
//}

//template <std::size_t Capacity>
//class sponge_absorber
//{
//public:
//	static constexpr auto byte_width = state_properties<Capacity>::byte_width;
//	static constexpr auto byte_capacity = state_properties<Capacity>::byte_width;
//	static constexpr auto byte_rate = state_properties<Capacity>::byte_rate;

//private:
//	state_type state_;
//	std::size_t bytes_absorbed_;

//public:
//	sponge_absorber()
//		: bytes_absorbed_()
//	{}

//	sponge_absorber(const void* data, std::size_t size)
//		: bytes_absorbed_()
//	{
//		(*this)(data, size);
//	}

//	void operator () (const void* data, std::size_t size)
//	{
//		auto data_bytes = static_cast<const std::uint8_t*>(data);

//		while (size != 0)
//		{
//			while (bytes_absorbed_ == 0 && size >= state_type::byte_rate)
//			{
//				for (std::size_t i = 0; i != state_type::byte_rate / state_type::byte_width; ++i)
//				{
//					lane_type lane;
//					std::memcpy(&lane, data_bytes + i * state_type::byte_width, state_type::byte_width);
//					*(state_[0] + i) ^= lane;
//				}

//				data_bytes += state_type::byte_rate;
//				size -= state_type::byte_rate;

//				state_.transform();
//			}

//			if (size != 0)
//			{
//				reinterpret_cast<std::uint8_t*>(state_.data())[bytes_absorbed_] ^= *data_bytes;

//				++data_bytes;
//				--size;

//				if (++bytes_absorbed_ == state_type::byte_rate)
//				{
//					state_.transform();
//					bytes_absorbed_ = 0;
//				}
//			}
//		}
//	}

//	std::size_t bytes_absorbed() const
//	{
//		return bytes_absorbed_;
//	}

//	const state_type& internal_state() const
//	{
//		return state_;
//	}

//	state_type& internal_state()
//	{
//		return state_;
//	}
//};

//template <typename StateType, std::uint8_t domain = 0, std::uint8_t domain_bits = 0>
//class sponge_squeezer
//{
//public:
//	static_assert(domain_bits <= 6, "More than 6 domain bits are not supported.");

//	typedef StateType state_type;
//	typedef typename state_type::lane_type lane_type;

//private:
//	state_type state_;
//	std::size_t bytes_squeezed_;

//public:
//	sponge_squeezer(sponge_absorber<state_type> absorber)
//		: state_(absorber.internal_state())
//		, bytes_squeezed_()
//	{
//		reinterpret_cast<std::uint8_t*>(state_.data())[absorber.bytes_absorbed()] ^= (1u << domain_bits) | domain;
//		reinterpret_cast<std::uint8_t*>(state_.data())[state_type::byte_rate - 1] ^= 128u;
//		state_.transform();
//	}

//	void operator () (void* buf, std::size_t size)
//	{
//		auto buf_bytes = static_cast<std::uint8_t*>(buf);

//		while (size != 0)
//		{
//			while (bytes_squeezed_ == 0 && size >= state_type::byte_rate)
//			{
//				std::memcpy(buf_bytes, state_.data(), state_type::byte_rate);

//				buf_bytes += state_type::byte_rate;
//				size -= state_type::byte_rate;

//				state_.transform();
//			}

//			if (size != 0)
//			{
//				const auto copy_size = std::min(size, state_type::byte_rate - bytes_squeezed_);
//				const auto ttate_bytes = reinterpret_cast<std::uint8_t*>(state_.data());

//				std::memcpy(buf_bytes, state_bytes + bytes_squeezed_, copy_size);

//				buf_bytes += copy_size;
//				size -= copy_size;
//				bytes_squeezed_ += copy_size;

//				if (bytes_squeezed_ == state_type::byte_rate)
//				{
//					state_.transform();
//					bytes_squeezed_ = 0;
//				}
//			}
//		}
//	}

//	std::size_t bytes_squeezed() const
//	{
//		return bytes_squeezed_;
//	}

//	const state_type& internal_state() const
//	{
//		return state_;
//	}

//	state_type& internal_state()
//	{
//		return state_;
//	}
//};
