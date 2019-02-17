# **KeyListener**

## Using
---------------------------------
To get started, connect the header file.
```php
#include <KeyListener>
```
Simple example
```php
public void:OnPlayerKeyDown(playerid, keyid) {
	new buffer[64];
	format(buffer, sizeof(buffer), "KeyDown: %d", keyid);
	SendClientMessage(playerid, -1, buffer);
}
public void:OnPlayerKeyUp(playerid, keyid) {
	new buffer[64];
	format(buffer, sizeof(buffer), "KeyUp: %d", keyid);
	SendClientMessage(playerid, -1, buffer);
}
```
