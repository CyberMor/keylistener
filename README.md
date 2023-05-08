# **KeyListener**

## Using
---------------------------------
To get started, connect the header file.
```php
#include <KeyListener>
```
Simple example
```php
public void:OnPlayerKeyDown(player, key)
{
	new buffer[64];
	format(buffer, sizeof(buffer), "KeyDown: %d", key);
	SendClientMessage(player, -1, buffer);
}
public void:OnPlayerKeyUp(player, key)
{
	new buffer[64];
	format(buffer, sizeof(buffer), "KeyUp: %d", key);
	SendClientMessage(player, -1, buffer);
}
```
