// Paste in your dll source doesn't matter.
// Credits to ADSF or whatever.

namespace Scanner {
	BOOL compare(const BYTE* location, const BYTE* aob, const char* mask) {
		for (; *mask; ++aob, ++mask, ++location) {
			__try {
				if (*mask == 'x' && *location != *aob)
					return 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return 0;
			}
		}
		return 1;
	}
	DWORD find_Pattern(BYTE* pattern, char* mask, BYTE protection = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
		SYSTEM_INFO SI = { 0 };
		GetSystemInfo(&SI);
		DWORD start = (DWORD)SI.lpMinimumApplicationAddress;
		DWORD end = (DWORD)SI.lpMaximumApplicationAddress;
		MEMORY_BASIC_INFORMATION mbi;
		while (start < end && VirtualQuery((void*)start, &mbi, sizeof(mbi))) {
			if ((mbi.State & MEM_COMMIT) && (mbi.Protect & protection) && !(mbi.Protect & PAGE_GUARD)) {
				for (DWORD i = (DWORD)mbi.BaseAddress; i < (DWORD)mbi.BaseAddress + mbi.RegionSize; ++i) {
					if (compare((BYTE*)i, pattern, mask)) {
						return i;
					}
				}
			}
			start += mbi.RegionSize;
		}
		return 0;
	}
	int Scan(DWORD mode, char* content, char* mask) {
		return find_Pattern((BYTE*)content, mask, mode);
	}
}

// Go to ur main void and paste this

	DWORD v2 = Scanner::Scan(PAGE_READWRITE, (char*)&ScriptContextVFTable, (char*)"xxxx");
  
  // Paste at top
  
  DWORD ScriptContextVFTable = x(0x001F6670C); // Address
