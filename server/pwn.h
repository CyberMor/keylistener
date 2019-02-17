#ifndef _SERVER_H_
#define _SERVER_H_

#include <vector>

#include <pawn/amx/amx.h>
#include <pawn/plugincommon.h>
#include <raknet/networktypes.h>

namespace pawn {

	class script {
	private:

		static std::vector<script> scripts_onplayerkeydown;
		static std::vector<script> scripts_onplayerkeyup;

		AMX * const amx;
		int index_onplayerkeydown = 0;
		int index_onplayerkeyup = 0;

		script(AMX* _amx) : amx(_amx) {}

		inline void onplayerkeydown(
			int player_id,
			uint32_t key_id
		) {
			int retval;
			amx_Push(this->amx, (cell)(key_id));
			amx_Push(this->amx, (cell)(player_id));
			amx_Exec(this->amx, &retval, this->index_onplayerkeydown);
		}

		inline void onplayerkeyup(
			int player_id,
			uint32_t key_id
		) {
			int retval;
			amx_Push(this->amx, (cell)(key_id));
			amx_Push(this->amx, (cell)(player_id));
			amx_Exec(this->amx, &retval, this->index_onplayerkeyup);
		}

	public:

		static void reg(
			AMX *amx
		) {
			
			int tmp_index;
			script new_obj = script(amx);

			if (!amx_FindPublic(amx, "OnPlayerKeyDown", &tmp_index) &&
				tmp_index >= 0
			) {
				new_obj.index_onplayerkeydown = tmp_index;
				scripts_onplayerkeydown.push_back(new_obj);
			}

			if (!amx_FindPublic(amx, "OnPlayerKeyUp", &tmp_index) &&
				tmp_index >= 0
			) {
				new_obj.index_onplayerkeyup = tmp_index;
				scripts_onplayerkeyup.push_back(new_obj);
			}

		}

		static inline void onplayerkeydown_all(
			int player_id,
			uint32_t key_id
		) {
			for (auto i : scripts_onplayerkeydown) i.onplayerkeydown(player_id, key_id);
		}

		static inline void onplayerkeyup_all(
			int player_id,
			uint32_t key_id
		) {
			for (auto i : scripts_onplayerkeyup) i.onplayerkeyup(player_id, key_id);
		}

	};

}

std::vector<pawn::script> pawn::script::scripts_onplayerkeydown;
std::vector<pawn::script> pawn::script::scripts_onplayerkeyup;

#endif