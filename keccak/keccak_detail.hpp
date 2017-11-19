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

#ifndef KECCAK_DETAIL_36959711
#define KECCAK_DETAIL_36959711

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <array>
#include <limits>
#include <type_traits>

namespace keccak {
namespace detail {

template <typename Byte>
class basic_memory_view
{
public:
	static_assert(std::is_pod_v<Byte>,
		"Bytes should be POD.");

	using byte_type = Byte;

private:
	byte_type* _data{};
	std::size_t _size{};

public:
	constexpr basic_memory_view() noexcept = default;

	constexpr basic_memory_view(byte_type* data, std::size_t size) noexcept
		: _data{ data }
		, _size{ size }
	{}

	template <typename Container>
	constexpr basic_memory_view(Container& container) noexcept
		: basic_memory_view(std::data(container), std::size(container))
	{}

	template <typename Container>
	constexpr basic_memory_view(const Container& container) noexcept
		: basic_memory_view(std::data(container), std::size(container))
	{}

	constexpr auto& operator [] (std::size_t i) const noexcept
	{
		return _data[i];
	}

	constexpr auto data() const noexcept
	{
		return _data;
	}

	constexpr auto size() const noexcept
	{
		return _size;
	}

	constexpr auto subview(std::size_t offset) const noexcept
	{
		return subview(offset, size() - offset);
	}

	constexpr auto subview(std::size_t offset, std::size_t size) const noexcept
	{
		return basic_memory_view(data() + offset, size);
	}
};

using memory_view = basic_memory_view<std::byte>;
using cmemory_view = basic_memory_view<const std::byte>;

template <typename Container>
static memory_view data_as_bytes(Container& container)
{
	return memory_view{
		reinterpret_cast<std::byte*>(std::data(container)),
		std::size(container) * sizeof container[0] };
}

template <typename Container>
static cmemory_view data_as_bytes(const Container& container)
{
	return cmemory_view{
		reinterpret_cast<const std::byte*>(std::data(container)),
		std::size(container) * sizeof container[0] };
}

inline void memory_xor(
	memory_view buffer,
	const std::byte* source0,
	const std::byte* source1) noexcept
{
	for (std::size_t i{}; i < buffer.size(); ++i)
	{
		buffer[i] = source0[i] ^ source1[i];
	}
}

inline void memory_xor(
	memory_view buffer, const std::byte* source) noexcept
{
	for (std::size_t i{}; i < buffer.size(); ++i)
	{
		buffer[i] ^= source[i];
	}
}

template <
	typename Word,
	typename = std::enable_if_t<std::is_unsigned_v<Word>>
>
static constexpr Word rol(Word w, unsigned amount) noexcept
{
	/*
	 * There is a way to implement this without
	 * needing a conditional, but not all compilers
	 * understand this pattern yet. Since all rotation
	 * amounts are compile-time constants,
	 * this is fine for now.
	 */

	constexpr auto word_bits{
		std::numeric_limits<Word>::digits
	};

	return (amount == 0) ? w :
		((w << amount) | (w >> (word_bits - amount)));
}

static_assert(std::is_same_v<
	std::underlying_type_t<std::byte>,
	std::uint8_t>, "std::byte is not 8 bit wide.");

static constexpr unsigned msb_pos(
	unsigned long long value, unsigned result = 0) noexcept
{
	return value <= 1 ? result : msb_pos(value / 2, result + 1);
}

using lane_type = std::uint64_t;
using state_type = std::array<std::array<lane_type, 5>, 5>;

static_assert(
	sizeof(state_type) == sizeof(lane_type) * 25, "state_type has padding.");

static constexpr std::size_t n_rounds{
	12 + 2 * msb_pos(std::numeric_limits<lane_type>::digits)
};

enum class cipher_mode : std::uint8_t
{
	encrypt,
	decrypt,
};

static constexpr std::array<std::array<unsigned, 5>, 5> rotation_offsets
{ {
	{{ 0, 1, 62, 28, 27 }},
	{{ 36, 44, 6, 55, 20 }},
	{{ 3, 10, 43, 25, 39 }},
	{{ 41, 45, 15, 21, 8 }},
	{{ 18, 2, 61, 56, 14 }},
} };

static constexpr std::array<std::uint64_t, n_rounds> round_constants
{ {
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
} };

/*
 * Keccak round function
 */

inline void keccak_f(state_type& s) noexcept
{
	for (std::size_t i = 0; i < round_constants.size(); ++i)
	{
		auto c0 = s[0][0] ^ s[1][0] ^ s[2][0] ^ s[3][0] ^ s[4][0];
		auto c1 = s[0][1] ^ s[1][1] ^ s[2][1] ^ s[3][1] ^ s[4][1];
		auto c2 = s[0][2] ^ s[1][2] ^ s[2][2] ^ s[3][2] ^ s[4][2];
		auto c3 = s[0][3] ^ s[1][3] ^ s[2][3] ^ s[3][3] ^ s[4][3];
		auto c4 = s[0][4] ^ s[1][4] ^ s[2][4] ^ s[3][4] ^ s[4][4];

		const auto d0 = c4 ^ rol(c1, 1);
		const auto d1 = c0 ^ rol(c2, 1);
		const auto d2 = c1 ^ rol(c3, 1);
		const auto d3 = c2 ^ rol(c4, 1);
		const auto d4 = c3 ^ rol(c0, 1);

		const auto s00 = rol(s[0][0] ^ d0, rotation_offsets[0][0]);
		const auto s01 = rol(s[1][1] ^ d1, rotation_offsets[1][1]);
		const auto s02 = rol(s[2][2] ^ d2, rotation_offsets[2][2]);

		s[0][0] = s00 ^ (~s01 & s02) ^ round_constants[i];

		const auto s20 = rol(s[0][1] ^ d1, rotation_offsets[0][1]);
		const auto s03 = rol(s[3][3] ^ d3, rotation_offsets[3][3]);

		s[0][1] = s01 ^ (~s02 & s03);

		const auto s40 = rol(s[0][2] ^ d2, rotation_offsets[0][2]);
		const auto s04 = rol(s[4][4] ^ d4, rotation_offsets[4][4]);

		s[0][2] = s02 ^ (~s03 & s04);

		const auto s10 = rol(s[0][3] ^ d3, rotation_offsets[0][3]);

		s[0][3] = s03 ^ (~s04 & s00);

		const auto s30 = rol(s[0][4] ^ d4, rotation_offsets[0][4]);

		s[0][4] = s04 ^ (~s00 & s01);

		const auto s31 = rol(s[1][0] ^ d0, rotation_offsets[1][0]);
		const auto s11 = rol(s[1][4] ^ d4, rotation_offsets[1][4]);
		const auto s12 = rol(s[2][0] ^ d0, rotation_offsets[2][0]);

		s[1][0] = s10 ^ (~s11 & s12);

		const auto s13 = rol(s[3][1] ^ d1, rotation_offsets[3][1]);

		s[1][1] = s11 ^ (~s12 & s13);

		const auto s21 = rol(s[1][2] ^ d2, rotation_offsets[1][2]);
		const auto s14 = rol(s[4][2] ^ d2, rotation_offsets[4][2]);

		s[1][2] = s12 ^ (~s13 & s14);

		const auto s41 = rol(s[1][3] ^ d3, rotation_offsets[1][3]);
		
		s[1][3] = s13 ^ (~s14 & s10);
		s[1][4] = s14 ^ (~s10 & s11);

		const auto s22 = rol(s[2][3] ^ d3, rotation_offsets[2][3]);

		s[2][0] = s20 ^ (~s21 & s22);

		const auto s32 = rol(s[2][1] ^ d1, rotation_offsets[2][1]);
		const auto s23 = rol(s[3][4] ^ d4, rotation_offsets[3][4]);

		s[2][1] = s21 ^ (~s22 & s23);

		const auto s24 = rol(s[4][0] ^ d0, rotation_offsets[4][0]);

		s[2][2] = s22 ^ (~s23 & s24);
		s[2][3] = s23 ^ (~s24 & s20);

		const auto s42 = rol(s[2][4] ^ d4, rotation_offsets[2][4]);

		s[2][4] = s24 ^ (~s20 & s21);

		const auto s43 = rol(s[3][0] ^ d0, rotation_offsets[3][0]);

		s[3][0] = s30 ^ (~s31 & s32);

		const auto s33 = rol(s[3][2] ^ d2, rotation_offsets[3][2]);

		s[3][1] = s31 ^ (~s32 & s33);

		const auto s34 = rol(s[4][3] ^ d3, rotation_offsets[4][3]);

		s[3][2] = s32 ^ (~s33 & s34);
		s[3][3] = s33 ^ (~s34 & s30);
		s[3][4] = s34 ^ (~s30 & s31);
		s[4][0] = s40 ^ (~s41 & s42);

		const auto s44 = rol(s[4][1] ^ d1, rotation_offsets[4][1]);

		s[4][1] = s41 ^ (~s42 & s43);
		s[4][2] = s42 ^ (~s43 & s44);
		s[4][3] = s43 ^ (~s44 & s40);
		s[4][4] = s44 ^ (~s40 & s41);
	}
}

/*
 * Classes
 */

class capacity
{
	std::uint8_t _n_bytes;

public:
	template <std::size_t N_Bits>
	static constexpr capacity make() noexcept
	{
		return capacity(static_cast<std::uint8_t>(N_Bits / 8));

		static_assert(N_Bits % width() == 0,
			"Rate / width combination not supported.");

		static_assert(N_Bits < 25 * width(), "Capacity too high.");

		static_assert(sizeof(state_type) <
			std::numeric_limits<std::uint8_t>::max(), "State too wide.");
	}

	constexpr static std::size_t width() noexcept
	{
		return std::numeric_limits<lane_type>::digits;
	}

	constexpr static std::size_t byte_width() noexcept
	{
		return sizeof(lane_type);
	}

	constexpr std::size_t n_bits() const noexcept
	{
		return n_bytes() * 8;
	}

	constexpr std::size_t n_bytes() const noexcept
	{
		return _n_bytes;
	}

	constexpr std::size_t rate() const noexcept
	{
		return byte_rate() * 8;
	}

	constexpr std::size_t byte_rate() const noexcept
	{
		return sizeof(state_type) - n_bytes();
	}

	constexpr std::size_t n_elements() const noexcept
	{
		return rate() / width();
	}

private:
	explicit constexpr capacity(std::uint8_t n_bytes) noexcept
		: _n_bytes{ n_bytes }
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

	constexpr std::byte pad() const
	{
		return static_cast<std::byte>(value() | 1u << size());
	}

private:
	explicit constexpr domain(std::uint8_t value)
		: _domain{ value }
	{}

	static constexpr std::uint8_t domain_size(std::uint8_t value)
	{
		return value == 0 ? 0 : static_cast<std::uint8_t>(1 + msb_pos(value));
	}
};

class sponge
{
	state_type _state{};
	std::size_t _bytes_processed{};
	capacity _capacity;
	bool _squeezing{ false };

public:
	explicit constexpr sponge(capacity cap) noexcept
		: _capacity(cap)
	{}

	constexpr auto byte_rate() const noexcept
	{
		return _capacity.byte_rate();
	}

	void absorb(cmemory_view data, domain dom) noexcept
	{
		if (_squeezing)
		{
			_squeezing = false;
			pad(dom);
			transform();
		}

		while (data.size() > 0)
		{
			const auto chunk{
				data_as_bytes(_state).subview(_bytes_processed,
					std::min(data.size(), byte_rate() - _bytes_processed))
			};

			memory_xor(chunk, data.data());

			data = data.subview(chunk.size());

			_bytes_processed += chunk.size();

			if (_bytes_processed == byte_rate())
			{
				transform();
			}
		}
	}

	void squeeze(memory_view buffer, domain dom) noexcept
	{
		if (!_squeezing)
		{
			_squeezing = true;
			pad(dom);
			transform();
		}

		while (buffer.size() > 0)
		{
			if (_bytes_processed == byte_rate())
			{
				transform();
			}

			const auto chunk{
				data_as_bytes(_state).subview(_bytes_processed,
					std::min(buffer.size(), byte_rate() - _bytes_processed))
			};

			std::memcpy(buffer.data(), chunk.data(), chunk.size());

			buffer = buffer.subview(chunk.size());

			_bytes_processed += chunk.size();
		}
	}

private:
	void pad(domain dom) noexcept
	{
		data_as_bytes(_state)[_bytes_processed] ^= dom.pad();
		data_as_bytes(_state)[_capacity.byte_rate() - 1] ^= std::byte{ 128u };
	}

	void transform() noexcept
	{
		keccak_f(_state);
		_bytes_processed = 0;
	}
};

class sponge_wrap
{
	state_type _state{};
	capacity _capacity;

public:
	sponge_wrap(capacity cap, cmemory_view key) noexcept
		: _capacity(cap)
	{
		/*
		 * We need to leave 1 byte for padding, as each block gets
		 * padded, unlike in the normal sponge mode.
		 */

		const auto duplex_rate{ byte_rate() - 1 };

		while (key.size() > duplex_rate)
		{
			absorb_transform(key, domain::make<1>());
			key = key.subview(duplex_rate);
		}

		absorb_transform(key, domain::make<0>());
	}

	constexpr std::size_t byte_rate() const noexcept
	{
		return _capacity.byte_rate();
	}

	void wrap(
		cmemory_view header,
		memory_view buffer,
		cmemory_view body,
		memory_view tag) noexcept
	{
		wrap_impl(header, buffer, body, tag, body);
	}

	void unwrap(
		cmemory_view header,
		memory_view buffer,
		cmemory_view body,
		memory_view tag) noexcept
	{
		wrap_impl(header, buffer, body, tag, buffer);
	}

private:
	void wrap_impl(
		cmemory_view header,
		memory_view buffer,
		cmemory_view body,
		memory_view tag,
		cmemory_view duplex_source) noexcept
	{
		/*
		 * We need to leave 1 byte for padding, as each block gets
		 * padded, unlike in the normal sponge mode.
		 */

		const auto duplex_rate{ byte_rate() - 1 };

		while (header.size() > duplex_rate)
		{
			absorb_transform(header, domain::make<0>());
			header = header.subview(duplex_rate);
		}

		absorb_transform(header, domain::make<1>());

		// assert buffer.size() >= body.size()

		while (body.size() > duplex_rate)
		{
			const auto chunk{
				buffer.subview(0, duplex_rate)
			};

			memory_xor(chunk, body.data(), data_as_bytes(_state).data());

			absorb_transform(
				duplex_source.subview(0, duplex_rate), domain::make<0>());

			body = body.subview(duplex_rate);
			buffer = buffer.subview(duplex_rate);
			duplex_source = duplex_source.subview(duplex_rate);
		}

		memory_xor(buffer, body.data(), data_as_bytes(_state).data());

		absorb_transform(duplex_source, domain::make<0>());

		// The full rate can be used as output.
		while (tag.size() > byte_rate())
		{
			std::memcpy(tag.data(), data_as_bytes(_state).data(), byte_rate());

			tag = tag.subview(byte_rate());

			absorb_transform({}, domain::make<0>());
		}

		std::memcpy(tag.data(), data_as_bytes(_state).data(), tag.size());
	}

	void absorb_transform(cmemory_view data, domain dom) noexcept
	{
		// assert(_capacity.byte_rate() >= buffer_size);
		// assert(_capacity.byte_rate() - 1 >= data_size);

		const auto chunk{
			data_as_bytes(_state).subview(0, data.size())
		};

		memory_xor(chunk, data.data());

		data_as_bytes(_state)[data.size()] ^= dom.pad();
		data_as_bytes(_state)[_capacity.byte_rate() - 1] ^= std::byte{ 128u };

		keccak_f(_state);
	}
};

class sponge_prg
{
	state_type _state{};
	std::size_t _bytes_processed{};
	capacity _capacity;
	bool _fetching{ false };

public:
	constexpr sponge_prg(capacity cap) noexcept
		: _capacity(cap)
	{}

	constexpr auto byte_rate() const noexcept
	{
		return _capacity.byte_rate() - 1;
	}

	void feed(cmemory_view data, domain dom) noexcept
	{
		if (_fetching)
		{
			_fetching = false;
			pad_and_transform(dom);
		}

		while (data.size() > 0)
		{
			const auto chunk{
				data_as_bytes(_state).subview(_bytes_processed,
					std::min(data.size(), byte_rate() - _bytes_processed))
			};

			memory_xor(chunk, data.data());

			data = data.subview(chunk.size());

			_bytes_processed += chunk.size();

			if (_bytes_processed == byte_rate())
			{
				pad_and_transform(dom);
			}
		}
	}

	void fetch(memory_view buffer, domain dom) noexcept
	{
		if (!_fetching)
		{
			_fetching = true;
			pad_and_transform(dom);
		}

		while (buffer.size() > 0)
		{
			const auto chunk{
				data_as_bytes(_state).subview(_bytes_processed,
					std::min(buffer.size(), byte_rate() - _bytes_processed))
			};

			std::memcpy(buffer.data(), chunk.data(), chunk.size());

			buffer = buffer.subview(chunk.size());

			_bytes_processed += chunk.size();

			if (_bytes_processed == byte_rate())
			{
				pad_and_transform(dom);
			}
		}
	}

	void pad_and_transform(domain dom) noexcept
	{
		data_as_bytes(_state)[_bytes_processed] ^= dom.pad();
		data_as_bytes(_state)[byte_rate()] ^= std::byte{ 128u };

		_bytes_processed = 0;

		keccak_f(_state);
	}
};

template <
	std::size_t CollisionResistance,
	std::size_t PreimageResistance,
	std::uint8_t Domain
>
class basic_hasher
{
public:
	static constexpr std::size_t collision_resistance{ CollisionResistance };
	static constexpr std::size_t preimage_resistance{ PreimageResistance };

	static constexpr std::size_t capacity{
		std::max(collision_resistance * 2, preimage_resistance * 2)
	};

	static constexpr std::size_t hash_size{
		std::max(collision_resistance * 2 / 8, preimage_resistance / 8)
	};

	using hash_type = std::array<std::byte, hash_size>;

private:
	sponge _sponge = sponge(capacity::make<capacity>());

public:
	constexpr basic_hasher() noexcept = default;

	basic_hasher(cmemory_view data) noexcept
		: basic_hasher()
	{
		update(data);
	}

	constexpr std::size_t byte_rate() const noexcept
	{
		return _sponge.byte_rate();
	}

	void reset() noexcept
	{
		*this = basic_hasher();
	}

	void update(cmemory_view data) noexcept
	{
		_sponge.absorb(data, domain::make<Domain>());
	}

	void finish(memory_view buffer) noexcept
	{
		_sponge.squeeze(buffer, domain::make<Domain>());
		reset();
	}

	hash_type finish() noexcept
	{
		hash_type hash;
		finish(hash);
		return hash;
	}
};

template <std::size_t SecurityStrength, cipher_mode Mode>
class basic_authenticated_cipher
{
public:
	static constexpr std::size_t security_strength{ SecurityStrength };
	static constexpr std::size_t capacity{ security_strength * 2 };

private:
	sponge_wrap _wrapper;

public:
	basic_authenticated_cipher(cmemory_view key) noexcept
		: _wrapper(capacity::make<capacity>(), key)
	{}

	void transform(
		cmemory_view header,
		memory_view buffer,
		cmemory_view body,
		memory_view tag) noexcept
	{
		if constexpr (Mode == cipher_mode::encrypt)
		{
			_wrapper.wrap(header, buffer, body, tag);
		}
		else if constexpr (Mode == cipher_mode::decrypt)
		{
			_wrapper.unwrap(header, buffer, body, tag);
		}
		else
		{
			static_assert(
				Mode == cipher_mode::encrypt ||
				Mode == cipher_mode::decrypt,
				"Invalid cipher mode.");
		}
	}

	void operator () (
		cmemory_view header,
		memory_view buffer,
		cmemory_view body,
		memory_view tag) noexcept
	{
		transform(header, buffer, body, tag);
	}
};

template <typename UIntType, std::size_t SecurityStrength>
class basic_random_engine
{
public:
	static constexpr std::size_t state_size{ sizeof(state_type) };
	static constexpr std::size_t security_strength{ SecurityStrength };
	static constexpr std::size_t capacity{ security_strength * 2 };

	using result_type = UIntType;

private:
	static constexpr domain _dom = domain::make<21>();

	sponge_prg _prg = sponge_prg(capacity::make<capacity>());

public:
	basic_random_engine(cmemory_view seed) noexcept
	{
		reseed(seed);
	}

	void reseed(cmemory_view seed) noexcept
	{
		_prg.feed(seed, _dom);
	}

	void extract(memory_view buffer) noexcept
	{
		_prg.fetch(buffer, _dom);
	}

	void operator () (memory_view buffer) noexcept
	{
		extract(buffer);
	}

	result_type operator () () noexcept
	{
		result_type r;
		extract({ reinterpret_cast<std::byte*>(&r), sizeof r });
		return r;
	}

	static constexpr result_type min() noexcept
	{
		return std::numeric_limits<result_type>::min();
	}

	static constexpr result_type max() noexcept
	{
		return std::numeric_limits<result_type>::max();
	}
};
} // namespace detail
} // namespace keccak

#endif
