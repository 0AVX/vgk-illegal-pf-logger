#ifndef NT
#define NT

#include <Windows.h>
#include <ntstatus.h>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>

#pragma comment(lib, "ntdll.lib")

namespace utils
{
	template <typename ty>
	concept constrain_pointer = (std::is_integral_v<ty> && sizeof(ty) == sizeof(void*)) || std::is_pointer_v<ty>;
}

namespace nt
{
	extern "C"
	{
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

		enum SYSTEM_INFORMATION_CLASS
		{
			SystemModuleInformation = 11
		};

		typedef struct _SYSTEM_MODULE
		{
			HANDLE Section;
			PVOID MappedBase;
			PVOID ImageBase;
			ULONG ImageSize;
			ULONG Flags;
			USHORT LoadOrderIndex;
			USHORT InitOrderIndex;
			USHORT LoadCount;
			USHORT OffsetToFileName;
			UCHAR  FullPathName[255];
		} SYSTEM_MODULE, * PSYSTEM_MODULE;

		typedef struct _SYSTEM_MODULE_INFORMATION
		{
			ULONG NumberOfModules;
			SYSTEM_MODULE Modules[1];
		} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

		__declspec(dllimport) NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	}

	constexpr auto page_size = 0x1000;

	class intel
	{
		static constexpr auto ioctl_code = 0x80862007;

		std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)> handle
			= { CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0), CloseHandle };

		bool copy(const utils::constrain_pointer auto source, const utils::constrain_pointer auto destination, const std::size_t size) const
		{
			struct command
			{
			public:
				enum : std::uint64_t
				{
					copy_memory = 51
				} type;

			private:
				std::uint64_t _;

			public:
				std::uintptr_t source;
				std::uintptr_t destination;
				std::size_t size;
			};

			command command;
			command.type = command::copy_memory;
			command.source = (std::uintptr_t)source;
			command.destination = (std::uintptr_t)destination;
			command.size = size;

			return DeviceIoControl(handle.get(), ioctl_code, &command, sizeof(command), nullptr, 0, nullptr, nullptr);
		}

	public:
		template <class ty>
		std::optional<ty> read(const utils::constrain_pointer auto address) const
		{
			ty value;
			return copy(address, &value, sizeof(ty)) ? std::make_optional(value) : std::nullopt;
		}

		template <class ty>
		bool write(const utils::constrain_pointer auto address, const ty& value) const
		{
			return copy(&value, address, sizeof(ty));
		}

		explicit intel()
		{
			if (!handle)
				std::abort();
		}

		static intel& get()
		{
			static intel instance;
			return instance;
		}

		intel(const intel&) = delete;
		intel(intel&&) = delete;
		intel& operator=(const intel&) = delete;
		intel& operator=(intel&&) = delete;
	};

	struct driver
	{
		std::uintptr_t base;
		std::uint32_t size;

		static std::optional<driver> get(const std::string& name)
		{
			ULONG size;
			if (ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size) != STATUS_INFO_LENGTH_MISMATCH)
				return std::nullopt;

			const auto loaded_modules_buffer = std::make_unique<std::uint8_t[]>(size);

			if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, loaded_modules_buffer.get(), size, nullptr)))
				return std::nullopt;

			const auto loaded_modules = (PSYSTEM_MODULE_INFORMATION)loaded_modules_buffer.get();

			for (auto i = 0u; i < loaded_modules->NumberOfModules; ++i)
				if (std::string_view((char*)loaded_modules->Modules[i].FullPathName).contains(name))
					return driver{ (std::uintptr_t)loaded_modules->Modules[i].ImageBase, loaded_modules->Modules[i].ImageSize };

			return std::nullopt;
		}
	};
}

namespace utils
{
	template <std::uint32_t signature_string_size>
	std::uintptr_t scan_signature(const utils::constrain_pointer auto start, const std::uint32_t size, const char(&signature)[signature_string_size])
	{
		constexpr auto signature_size = signature_string_size - 1;

		for (auto i = (std::uintptr_t)start; i < ((std::uintptr_t)start + size) - signature_size; ++i)
		{
			for (auto x = 0u; x < signature_size; ++x)
			{
				if (signature[x] != 0xCC && signature[x] != nt::intel::get().read<char>(i + x))
					break;

				if (x + 1 == signature_size)
					return i;
			}
		}

		return 0;
	}
}

#endif