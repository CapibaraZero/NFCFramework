# CapibaraZero NFC Framework

A library to interract easily with PN532 and build attack for the CapibaraZero based on Adafruit_PN532.

It includes also a useful wrapper around the NFC tag to get more information simply using the method in the class.

To set I2C pins, use the following build flags: PN532_IRQ_PIN and PN532_RST_PIN

## Features

- ISO14443A card reader
- Mifare card writer
- Read tag UID
- Dump all blocks in a tag
- Card formatter(mifare only)
- NTag2xx support(writer/reader)

### TODO
- Add full working card emulation
- Add felica support 

### References

[Tag structure](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/magic_cards_notes.md#mifare-classic)

[Adafruit_PN532](https://github.com/adafruit/Adafruit-PN532)
