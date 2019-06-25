python

class FkReloadAll(gdb.Command):
  "Reload all."
  def __init__ (self):
    super(FkReloadAll, self).__init__("jra", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)

  def invoke(self, arg, from_tty):
    gdb.execute("load build/m0-fk/bootloader/bootloader.elf")
    gdb.execute("load build/m0-fk/blink/blink-pic-fkb.elf")
    gdb.execute("monitor reset")

end

python FkReloadAll()

target extended-remote :2331
jra
b Dummy_Handler
b invoke_pic
monitor reset
continue
