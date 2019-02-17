#ifndef _NET_H_
#define _NET_H_

#include <raknet/bitstream.h>
#include <raknet/networktypes.h>

#include "main.h"
#include "mem.hpp"

#ifdef _WIN32
#define RAKNET_RECEIVE_OFFSET						10
#define RAKNET_DEALLOCATE_PACKET_OFFSET				12
#else
#define RAKNET_RECEIVE_OFFSET						11
#define RAKNET_DEALLOCATE_PACKET_OFFSET				13
#endif

constexpr char const
#ifdef _WIN32
*pattern = "\x64\xA1\x00\x00" \
"\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x51" \
"\x68\x18\x0E\x00\x00\xE8\xFF\xFF\xFF\xFF\x83" \
"\xC4\x04\x89\x04\x24\x85\xC0\xC7\x44\x24\xFF" \
"\x00\x00\x00\x00\x74\x16",
*mask = "xxxxxxxxxxxxxxxx????x????xxxxxxxxxxx?xxxxxx";
#else
*pattern = "\x04\x24\xFF\xFF" \
"\xFF\xFF\x89\x75\xFF\x89\x5D\xFF\xE8\xFF\xFF" \
"\xFF\xFF\x89\x04\x24\x89\xC6\xE8\xFF\xFF\xFF" \
"\xFF\x89\xF0\x8B\x5D\xFF\x8B\x75\xFF\x89\xEC" \
"\x5D\xC3",
*mask = "xx????xx?xx?x????xxxxxx????xxxx?xx?xxxx";
#endif

typedef Packet*	(THISCALL *raknet_receive_t)			(void* ppRakServer);
typedef void	(THISCALL *raknet_deallocatepacket_t)	(void* ppRakServer, Packet *packet);

class raknet {
private:

	static void *rakserver;

	static raknet_receive_t				func_receive;
	static raknet_deallocatepacket_t	func_deallocatepacket;

public:

	static void init(
		void *rakserver
	) {
		raknet::rakserver = rakserver;
		const auto rakserver_vtable = *reinterpret_cast<uint32_t**>(rakserver);
		raknet::func_receive = reinterpret_cast<raknet_receive_t>(rakserver_vtable[RAKNET_RECEIVE_OFFSET]);
		raknet::func_deallocatepacket = reinterpret_cast<raknet_deallocatepacket_t>(rakserver_vtable[RAKNET_DEALLOCATE_PACKET_OFFSET]);
	}

	static inline Packet* receive() {
		return raknet::func_receive(rakserver);
	}

	static inline void deallocate_packet(Packet *packet) {
		raknet::func_deallocatepacket(rakserver, packet);
	}

};

void						*raknet::rakserver = nullptr;
raknet_receive_t			raknet::func_receive;
raknet_deallocatepacket_t	raknet::func_deallocatepacket;

namespace net {

	class thiscall_hooks {
	public:
		static Packet* THISCALL hook_receive(void *_this) {
			Packet *packet = nullptr;
			while (packet = raknet::receive()) {
				switch (*packet->data) {
				case KL_PACKET_KEYDOWN:
					pawn::script::onplayerkeydown_all(packet->playerIndex, *(uint32_t*)(packet->data + 1));
					raknet::deallocate_packet(packet);
					break;
				case KL_PACKET_KEYUP:
					pawn::script::onplayerkeyup_all(packet->playerIndex, *(uint32_t*)(packet->data + 1));
					raknet::deallocate_packet(packet);
					break;
				default:
					return packet;
				}
			} return packet;
		}
	};

	static memory::hooks::jump_hook *hook_rakserver;
	static void* STDCALL func_hook_getrakserver() {
		
		void *temp;
		void *rakserver;

		temp = hook_rakserver->get_original_addr();
		delete hook_rakserver;

		if (rakserver = ((void*(*)())(temp))()) {
			raknet::init(rakserver);
			auto vtable = *((void***)(rakserver));
			memory::unprotect_scope scope_receive(&vtable[RAKNET_RECEIVE_OFFSET], sizeof(void*));
			vtable[RAKNET_RECEIVE_OFFSET] = reinterpret_cast<void*>(&thiscall_hooks::hook_receive);
		}

		return rakserver;

	}

	static bool init(
		void *addr_server
	) {
		
		void *addr; memory::dword_t size;
		if (!memory::getmoduleinfo(addr_server, addr, size)) return false;
		memory::scanner net_scanner(addr, size);

		if (uint8_t *func_ptr = (uint8_t*)(net_scanner.find(pattern, mask)))
			return hook_rakserver = new memory::hooks::jump_hook(func_ptr - 7, func_hook_getrakserver);

		return false;

	}

	static inline void free() {
		delete hook_rakserver;
	}

};

#endif
