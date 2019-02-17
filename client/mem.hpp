#pragma once

#include <windows.h>

namespace memory {

	using byte_t = unsigned char;
	using word_t = unsigned short;
	using dword_t = unsigned int;
	using qword_t = unsigned long long;
	using address_t = unsigned long;

	constexpr address_t null = 0u;

	class unprotect_scope {
	private:

		void *addr;
		dword_t size;
		DWORD original_protect;

	public:

		unprotect_scope() : addr(nullptr), size(null) {};
		unprotect_scope(void *addr, const dword_t size) {
			this->addr = addr; this->size = size;
			VirtualProtect(this->addr, this->size, PAGE_EXECUTE_READWRITE, &this->original_protect);
		}

		~unprotect_scope() {
			VirtualProtect(this->addr, this->size, this->original_protect, nullptr);
		}

	};

	namespace hooks {

#pragma pack(push, 1)
		struct call {
			byte_t opcode = 0xE8;
			dword_t offset;
			call(const dword_t _offset) : offset(_offset) {}
			call() : offset(null) {}
		};
		struct jump {
			byte_t opcode = 0xE9;
			dword_t offset;
			jump(const dword_t _offset) : offset(_offset) {}
			jump() : offset(null) {}
		};
#pragma pack(pop)

		class jump_hook {
		private:

			bool status;
			void *inject_addr;
			void *target_addr;
			int offset;
			uint8_t original_data[sizeof(jump)];
			DWORD original_protect;

		public:

			jump_hook() = delete;
			template<class T1, class T2>
			jump_hook(T1 _inject_addr, T2 _target_addr) :
				inject_addr(reinterpret_cast<void*>(_inject_addr)), target_addr(reinterpret_cast<void*>(_target_addr)) {
				VirtualProtect(this->inject_addr, sizeof(jump), PAGE_EXECUTE_READWRITE, &this->original_protect);
				memcpy(this->original_data, this->inject_addr, sizeof(jump));
				*(jump*)(this->inject_addr) = jump(this->offset = (uint32_t)(this->target_addr) - ((uint32_t)(this->inject_addr) + sizeof(jump)));
				this->status = true;
			}

			inline void enable() {
				if (!this->status) {
					*reinterpret_cast<jump*>(this->inject_addr) = jump(this->offset);
					this->status = true;
				}
			}

			inline void disable() {
				if (this->status) {
					memcpy(this->inject_addr, this->original_data, sizeof(jump));
					this->status = false;
				}
			}

			inline void* get_original_addr() {
				return this->inject_addr;
			}

			~jump_hook() {
				disable();
				VirtualProtect(this->inject_addr, sizeof(jump), this->original_protect, nullptr);
			}

		};

		class call_hook {
		private:

			bool status;
			void *inject_addr;
			void *target_addr;
			int offset;
			uint8_t original_data[sizeof(call)];
			DWORD original_protect;

		public:

			call_hook() = delete;
			template<class T1, class T2>
			call_hook(T1 _inject_addr, T2 _target_addr) :
				inject_addr(reinterpret_cast<void*>(_inject_addr)), target_addr(reinterpret_cast<void*>(_target_addr)) {
				VirtualProtect(this->inject_addr, sizeof(call), PAGE_EXECUTE_READWRITE, &this->original_protect);
				memcpy(this->original_data, this->inject_addr, sizeof(call));
				*reinterpret_cast<call*>(this->inject_addr) = call(this->offset = reinterpret_cast<uint32_t>(this->target_addr) - (reinterpret_cast<uint32_t>(this->inject_addr) + sizeof(call)));
				this->status = true;
			}

			inline void enable() {
				if (!this->status) {
					*reinterpret_cast<call*>(this->inject_addr) = call(this->offset);
					this->status = true;
				}
			}

			inline void disable() {
				if (this->status) {
					memcpy(this->inject_addr, this->original_data, sizeof(call));
					this->status = false;
				}
			}

			inline void* get_original_addr() {
				return this->inject_addr;
			}

			~call_hook() {
				disable();
				VirtualProtect(this->inject_addr, sizeof(call), this->original_protect, nullptr);
			}

		};

	}

	class scanner {
	private:

		address_t	region_addr;
		dword_t		region_size;

	public:

		scanner() = delete;
		scanner(scanner &value) = delete;
		template<class T1, class T2>
		scanner(T1 _region_addr, T2 _region_size) :
			region_addr(reinterpret_cast<address_t>(_region_addr)),
			region_size(static_cast<dword_t>(_region_size))
		{}

		// Найти шаблон
		void* find(const char *pattern, const char *mask) {
			byte_t *current_byte = reinterpret_cast<byte_t*>(this->region_addr);
			byte_t *last_byte = reinterpret_cast<byte_t*>(this->region_addr + this->region_size - strlen(mask));
			for (dword_t i; current_byte < last_byte; current_byte++) {
				for (i = 0; static_cast<byte_t>(mask[i]); i++) {
					if (((static_cast<byte_t>(mask[i]) == static_cast<byte_t>('x')) && (static_cast<byte_t>(pattern[i]) != current_byte[i]))) break;
				} if (!static_cast<byte_t>(mask[i])) break;
			} if (current_byte == last_byte) return nullptr;
			else return current_byte;
		}

	};

	static bool get_module_info(
		void *t_addr,
		void *&m_addr,
		dword_t &m_size
	) {				
		MEMORY_BASIC_INFORMATION info;
		if (!VirtualQuery(reinterpret_cast<void*>(t_addr), &info, sizeof(info))) return false;
		auto pe = (IMAGE_NT_HEADERS*)((memory::address_t)(info.AllocationBase) + ((IMAGE_DOS_HEADER*)(info.AllocationBase))->e_lfanew);
		if (pe->Signature != IMAGE_NT_SIGNATURE) return false;
		if (!(m_size = pe->OptionalHeader.SizeOfImage)) return false;
		m_addr = info.AllocationBase;
		return true;
	}

}
