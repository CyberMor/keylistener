#pragma once

#include "raknet/bitstream.h"
#include "raknet/rakclient.h"

#include "log.h"
#include "mem.hpp"

namespace net {

	static RakClientInterface *pRakClientInterface = nullptr;

	static memory::hooks::jump_hook *hook_rc_getrakclientinterface;
	static void __declspec(naked) handler_rc_getrakclientinterface() {

		static void *temp;

		__asm {
			pushad
			mov ebp, esp
			sub esp, __LOCAL_SIZE
		}

		temp = hook_rc_getrakclientinterface->get_original_addr();
		delete hook_rc_getrakclientinterface;

		pRakClientInterface = ((RakClientInterface*(*)())(temp))();

		__asm {
			mov esp, ebp
			popad
			mov eax, pRakClientInterface
			ret
		}

	}

	static bool init(
		uint32_t samp_dll
	) {

		void *m_addr;
		uint32_t m_size;
		uint32_t addr_rc_getrakclientinterface;

		if (net::pRakClientInterface) return false;
		if (!memory::get_module_info((void*)(samp_dll), m_addr, m_size)) return false;

		memory::scanner scanner(m_addr, m_size);
		
		if (!(addr_rc_getrakclientinterface = (uint32_t) scanner.find(
			"\x50\x00\x00\x00\x00\x00\x00\x00\x51\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x04\x89\x04\x24\x85\xC0\xC7\x44\x00\x00\x00\x00\x00\x00\x74\x1F",
			"x???????xx????x????xxxxxxxxxx??????xx"
		))) {
			logger::log("could not find address in memory for addr_rc_getrakclientinterface");
			return false;
		} if (!(hook_rc_getrakclientinterface = new memory::hooks::jump_hook(
			addr_rc_getrakclientinterface - 13,
			handler_rc_getrakclientinterface
		))) {
			logger::log("could not allocate memory for hook_rc_getrakclientinterface");
			return false;
		}

		return true;

	}

	static inline void free() {
		net::pRakClientInterface = nullptr;
	}

	static inline bool send(
		BitStream *bs
	) {
		return (net::pRakClientInterface ? net::pRakClientInterface->Send(bs, PacketPriority::HIGH_PRIORITY, PacketReliability::RELIABLE_ORDERED, '\0') : false);
	}

}
