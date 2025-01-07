import os
import pefile
import sys

def find_dlls(directory):
	
	dlls = []
	
	for root, dirs, files in os.walk(directory):
		
		for file in files:
		
			if file.lower().endswith('.dll'):
		
				dlls.append(os.path.join(root, file))
	
	return dlls

def extract_exports(dll_path):

	exports = []
	
	try:
	
		pe = pefile.PE(dll_path)

		if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
	
			for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	
				exports.append(exp.name.decode('utf-8') if exp.name else None)
	
		return exports
	
	except pefile.PEFormatError:
		
		return None

if __name__ == "__main__":

	dir_path = sys.argv[1]
	dlls = find_dlls(dir_path)
	
	for dll in dlls:
		print(" -"*32)
		print(f" [{dll}]:\n")
		exports = extract_exports(dll)
		if exports:
			for func in exports:
				if func:
					print(f"  [+] {func}")
		else:
			print("  [-] no exports found or other error.")
