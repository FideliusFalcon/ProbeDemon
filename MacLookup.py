from mac_vendor_lookup import AsyncMacLookup, MacLookup
import asyncio

class maclookup():
    def __init__(self):
        self.async_mac = AsyncMacLookup()
        self.mac = MacLookup()

    def UpdateVendorList(self):
        print("Updating MAC address vendor list")
        self.mac.update_vendors()
        print("MAC address vendor list has been updated")

    def lookup(self, addr):
        try:
            loop = asyncio.get_event_loop()
            vendor = loop.run_until_complete(self._lookup(addr))
            return vendor
        except Exception as e:
            print(e)
            print(addr)

    async def _lookup(self, mac_addr):
        return await self.async_mac.lookup(mac_addr)


if __name__ == "__main__":
    addr = "98:ED:5C:FF:EE:01"
    mac = maclookup()
    vendor = mac.lookup(addr)
    print(vendor)
