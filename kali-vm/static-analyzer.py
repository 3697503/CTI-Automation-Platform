import pefile

pe = pefile.PE('redline.exe')

print(pe.get_imphash())
print(pe.FILE_HEADER.dump_dict())