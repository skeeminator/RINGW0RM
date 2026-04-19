# Driver Loading

This patch allows loading of drivers regardless of their signature status. unsigned, test-signed, or even expired.  
The only requirement is that the driver must be set to **Boot Start**.
In theory, ELAM drivers could also be loaded, though this has not been tested.

### Usage

A batch script is provided to automatically create the driver service:

```bat
create_driver.bat DriverName
````

**Steps:**

1. Place your `.sys` driver file in the same folder as `create_driver.bat`.

2. Run the script from an elevated Command Prompt:

   ```bat
   create_driver.bat mydriver
   ```

   This will:

   * Copy the driver to `%SystemRoot%\System32\drivers`
   * Delete any existing service with the same name
   * Create a boot-start service for the driver

3. Restart the system.
   After reboot, the driver will load automatically.






