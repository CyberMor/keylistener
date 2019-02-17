#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <iostream>

#ifdef _WIN32
#include <windows.h>
#define STDCALL __stdcall
#define THISCALL __thiscall
#else
#define STDCALL
#define THISCALL
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#endif

namespace memory {

	// Базовые типы
	using byte_t	= unsigned char;
	using word_t	= unsigned short;
	using dword_t	= unsigned int;
	using qword_t	= unsigned long long;

	// Дополнительные типы
	using address_t = unsigned long;

	// Перехватчики
	namespace hooks {

#pragma pack(push, 1)
		struct call {
			byte_t opcode = 0xE8;
			dword_t offset;
			call(const dword_t _offset) : offset(_offset) {}
			call() : offset(0) {}
		};
		struct jump {
			byte_t opcode = 0xE9;
			dword_t offset;
			jump(const dword_t _offset) : offset(_offset) {}
			jump() : offset(0) {}
		};
#pragma pack(pop)

		// Перехватчик типа jump
		class jump_hook {
		private:

			bool status = false;
			void *inject_addr;
			void *target_addr;
			int offset;
			uint8_t original_data[sizeof(jump)];
#ifdef _WIN32
			DWORD original_protect;
#endif

		public:

			jump_hook() = delete;
			template<class T1, class T2>
			jump_hook(T1 _inject_addr, T2 _target_addr) :
				inject_addr(reinterpret_cast<void*>(_inject_addr)), target_addr(reinterpret_cast<void*>(_target_addr)) {
#ifdef _WIN32
				VirtualProtect(this->inject_addr, sizeof(jump), PAGE_EXECUTE_READWRITE, &this->original_protect);
#else
				mprotect((void*)((long)(this->inject_addr) & ~(sysconf(_SC_PAGE_SIZE) - 1)), sizeof(jump), PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
				memcpy(this->original_data, this->inject_addr, sizeof(jump));
				this->offset = (uint32_t)(this->target_addr) - ((uint32_t)(this->inject_addr) + sizeof(jump));
				this->enable();
			}

			inline void enable() {
				if (!this->status) {
					*(jump*)(this->inject_addr) = jump(this->offset);
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
#ifdef _WIN32
				VirtualProtect(this->inject_addr, sizeof(jump), this->original_protect, nullptr);
#else
				mprotect((void*)((long)(this->inject_addr) & ~(sysconf(_SC_PAGE_SIZE) - 1)), sizeof(jump), PROT_READ | PROT_EXEC);
#endif
			}

		};

		// Перехватчик типа call
		class call_hook {
		private:

			bool status = false;
			void *inject_addr;
			void *target_addr;
			int offset;
			uint8_t original_data[sizeof(call)];
#ifdef _WIN32
			DWORD original_protect;
#endif

		public:

			call_hook() = delete;
			template<class T1, class T2>
			call_hook(T1 _inject_addr, T2 _target_addr) :
				inject_addr(reinterpret_cast<void*>(_inject_addr)), target_addr(reinterpret_cast<void*>(_target_addr)) {
#ifdef _WIN32
				VirtualProtect(this->inject_addr, sizeof(call), PAGE_EXECUTE_READWRITE, &this->original_protect);
#else
				mprotect((void*)((long)(this->inject_addr) & ~(sysconf(_SC_PAGE_SIZE) - 1)), sizeof(call), PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
				memcpy(this->original_data, this->inject_addr, sizeof(call));
				this->offset = (uint32_t)(this->target_addr) - ((uint32_t)(this->inject_addr) + sizeof(call));
				this->enable();
			}

			inline void enable() {
				if (!this->status) {
					*(call*)(this->inject_addr) = call(this->offset);
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
#ifdef _WIN32
				VirtualProtect(this->inject_addr, sizeof(call), this->original_protect, nullptr);
#else
				mprotect((void*)((long)(this->inject_addr) & ~(sysconf(_SC_PAGE_SIZE) - 1)), sizeof(call), PROT_READ | PROT_EXEC);
#endif
			}

		};

	}

	// Заплатка снятия защиты
	class unprotect_scope {
	private:

		void *addr;
		dword_t size;

#ifdef _WIN32
		DWORD original_protect;
#endif

	public:

		unprotect_scope() = delete;
		unprotect_scope(void *addr, const dword_t size) {
			this->addr = addr; this->size = size;
#ifdef _WIN32
			VirtualProtect(this->addr, this->size, PAGE_EXECUTE_READWRITE, &this->original_protect);
#else
			this->addr = reinterpret_cast<void*>(reinterpret_cast<long>(this->addr) & ~(sysconf(_SC_PAGE_SIZE) - 1));
			mprotect(this->addr, this->size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
		}

		~unprotect_scope() {
#ifdef _WIN32
			VirtualProtect(this->addr, this->size, this->original_protect, nullptr);
#else
			mprotect(this->addr, this->size, PROT_READ | PROT_EXEC);
#endif
		}

	};

	// Сканер области памяти
	class scanner {
	private:

		address_t	region_addr;
		dword_t		region_size;

	public:

		scanner() = delete;
		scanner(scanner &value) = delete;
		template<class T1, class T2>
		scanner(T1 _region_addr, T2 _region_size) :
			region_addr(reinterpret_cast<address_t>(_region_addr)), region_size(static_cast<dword_t>(_region_size)) {
			static_assert(sizeof(T1) == sizeof(address_t), "invalid scanner address size");
		}

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
	
	// Получить размер файла
	static dword_t getfilesize(
		const char *filename
	) {

		dword_t result = 0;
		if (FILE *file = fopen(filename, "rb")) {
			fseek(file, 0, SEEK_END);
			result = ftell(file);
			fclose(file);
		}

		return result;

	}

	// Получить информацию о модуле памяти
	static bool getmoduleinfo(
		void *t_addr,
		void *&m_addr,
		dword_t &m_size
	) {
#ifdef _WIN32					
		MEMORY_BASIC_INFORMATION info;
		if (!VirtualQuery(reinterpret_cast<void*>(t_addr), &info, sizeof(info))) return false;
		auto pe = (IMAGE_NT_HEADERS*)((memory::address_t)(info.AllocationBase) + ((IMAGE_DOS_HEADER*)(info.AllocationBase))->e_lfanew);
		if (pe->Signature != IMAGE_NT_SIGNATURE) return false;
		if (!(m_size = pe->OptionalHeader.SizeOfImage)) return false;
		m_addr = info.AllocationBase;
#else
		Dl_info info{};
		struct stat buf {};
		if (!dladdr(t_addr, &info)) return false;
		m_addr = info.dli_fbase;
		if (!(m_size = getfilesize(info.dli_fname)))
			return false;
#endif
		return true;
	}

}

#endif