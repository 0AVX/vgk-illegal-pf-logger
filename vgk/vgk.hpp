#ifndef VGK
#define VGK

#include <cstdint>
#include <optional>
#include <type_traits>
#include <utils/utils.hpp>

namespace vgk
{
#pragma pack(push, 1)
	struct illegal_page_fault
	{
	public:
		bool finished;

	private:
		std::uint8_t _;

	public:
		std::uint8_t page[nt::page_size];

		template <typename ty = illegal_page_fault> requires (std::is_same_v<ty, illegal_page_fault> || utils::constrain_pointer<ty>)
		static std::optional<ty> get()
		{
			static const auto illegal_page_fault = ([]()
			{
				const auto vgk = nt::driver::get("vgk.sys");
				if (!vgk)
					return 0ull;

				const auto get_illegal_page_fault = utils::scan_signature(vgk->base, vgk->size, "\x48\x83\xEC\x28\x45\x33\xC0\x44");
				if (!get_illegal_page_fault)
					return 0ull;

				const auto relative = nt::intel::get().read<std::int32_t>(get_illegal_page_fault + 0xA);
				if (!relative)
					return 0ull;

				return get_illegal_page_fault + *relative + 0xE;
			})();

			if constexpr (std::is_same_v<ty, vgk::illegal_page_fault>)
				return nt::intel::get().read<vgk::illegal_page_fault>(illegal_page_fault);
			else
				return (ty)illegal_page_fault;
		}
	};
#pragma pack(pop)
}

#endif