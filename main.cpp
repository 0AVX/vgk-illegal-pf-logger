#include <cstdio>
#include <fstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <vgk/vgk.hpp>

/*
	VGK temporarily hooks "KiPageFault", as well as KPP routines, to intercept #PF exceptions.
	They flip the XD bit on possible entries in the PT, and thus manually mapped code will #PF on execution.
	If they intercept said code, then they will copy the page to their driver, flip the bit back, send an IPI to flush the TLB, and IRET.
	If the #PF was legitimate, then they will jump back to "KiPageFault".
	If an IOCTL was sent to query the page, and an illegal #PF was intercepted, then they will copy the page to the buffer, and clear the one in their driver.
*/

int main()
{
	using namespace std::chrono_literals;

	const auto illegal_page_fault = vgk::illegal_page_fault::get<std::uintptr_t>();
	if (!illegal_page_fault)
		return 1;

	if (!nt::intel::get().write(*illegal_page_fault, false))
		return 1;

	std::puts("[vgk-illegal-pf-logger] waiting");

	while (true)
	{
		const auto finished = nt::intel::get().read<bool>(*illegal_page_fault);
		if (!finished)
			return 1;

		if (!*finished)
		{
			std::this_thread::sleep_for(1s);
			continue;
		}

		const auto illegal_page_fault = vgk::illegal_page_fault::get();

		if (!illegal_page_fault || std::all_of(illegal_page_fault->page, illegal_page_fault->page + nt::page_size, [](const auto byte) { return !byte; }))
			return 1;

		std::ofstream("illegal-page-fault.bin", std::ios::binary).write((char*)illegal_page_fault->page, nt::page_size);
		std::puts("[vgk-illegal-pf-logger] captured");

		break;
	}

	std::puts("[vgk-illegal-pf-logger] finished");

	return 0;
}