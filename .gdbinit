python

import subprocess

class FkReloadAll(gdb.Command):
  "Reload all."
  def __init__ (self):
    super(FkReloadAll, self).__init__("jra", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)

  def invoke(self, arg, from_tty):
    gdb.execute("load build/m4-fk/bootloader/bootloader.elf")
    gdb.execute("load build/m4-fk/blink/blink-pic-fkb.elf")
    gdb.execute("monitor reset")

class FkRestart(gdb.Command):
  "Restart."
  def __init__ (self):
    super(FkRestart, self).__init__("rs", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)

  def invoke(self, arg, from_tty):
    gdb.execute("monitor reset")
    gdb.execute("c")

class FkReloadAllAndRun(gdb.Command):
  "Reload all."
  def __init__ (self):
    super(FkReloadAllAndRun, self).__init__("jrar", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)

  def invoke(self, arg, from_tty):
    made = subprocess.run(["make", "-j4"])
    if made.returncode != 0:
      return False
    gdb.execute("load build/m4-fk/bootloader/bootloader.elf")
    gdb.execute("load build/m4-fk/blink/blink-pic-fkb.elf")
    gdb.execute("monitor reset")
    gdb.execute("c")

end

python FkReloadAll()
python FkRestart()
python FkReloadAllAndRun()

target extended-remote :2331
# monitor exec SetRTTSearchRanges 0x20000000 64
add-symbol-file build/m4-fk/bootloader/bootloader.elf 0x0000
add-symbol-file build/m4-fk/blink/blink-pic-fkb.elf 0x4000
jra
b Dummy_Handler
# b invoke_pic
b test_object
monitor reset
continue
