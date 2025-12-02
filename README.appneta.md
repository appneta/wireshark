MacOS
=====

References
----------

* Code Signing:
  * <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html>
  * <https://developer.apple.com/library/archive/technotes/tn2206/_index.html>

* Notarizing
  * <https://developer.apple.com/documentation/xcode/notarizing_macos_software_before_distribution>

Prerequisites
-------------

```shell
 sudo gem install asciidoctor
 pip3 install dmgbuild
 brew install pkgconfig sparkle doxygen libp11 libgnutils gettext asciidoctor docbook docbook-xsl
 brew install --cask libndi
```

Build
-----

* Run one time only, or if moving to a new Wireshark revision

  ```shell
  tools/macos-setup-brew.sh --install-optional
  ```    

* Here are some exports you should execute before build

  ```shell
  export PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig
  export CMAKE_PREFIX_PATH=/opt/homebrew/opt/qt@6
  export PATH=/usr/local/opt/qt@6/bin:$PATH
  ```

* Build

  ```shell
  mkdir build; cd build
  cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 -G Ninja ..
  cmake --build .
  ```

* Build an app bundle (Wireshark.app)

  ```shell
  cmake --build . --target wireshark_app_bundle
  ```
  
* Choose a code signing certificate
  * in this example I want to use certificate #3 which was most recently created in XCode Preferences

  ```shell
  ❯ security find-identity -p codesigning -v login.keychain
  1) 02BD99C3D9CE9E301DF3D9D2E1C6148DFE95AC79 "Apple Development: fred.klassen@broadcom.com (PZ339J2MU7)"
  2) 0E3D74157F689870D378A291EBC3B1C927BA28D2 "Mac Developer: Fred Klassen (VRZWY3PKS3)"
  3) CE26B0A97A4D50197168F844813C929EEB3904F0 "Apple Development: Fred Klassen (VRZWY3PKS3)"
  3 valid identities found
  ```

  * for clarity I use `"Apple Development: Fred Klassen (VRZWY3PKS3)"`  but could also select `CE26B0A97A4D50197168F844813C929EEB3904F0` to resolve duplicates

* Sign the app bundle and verify that there are no errors

  ```shell
  ~/git/wireshark/build
  ❯ codesign --sign "Apple Development: Fred Klassen (VRZWY3PKS3)" --prefix "org.broadcom.appneta" \
    --entitlements ../packaging/macosx/entitlements.plist --timestamp --verbose --deep -f run/Wireshark.app
  run/Wireshark.app: replacing existing signature
  run/Wireshark.app: signed app bundle with Mach-O thin (arm64) [org.wireshark.Wireshark]
  ~/git/wireshark/build
  ❯ codesign --verify --deep --strict --verbose=2 run/Wireshark.app
  ...
  ```

* Test and note any error messages regarding missing libraries

  ```shell
  run/Wireshark.app/Contents/MacOS/Wireshark --help
  run/Wireshark.app/Contents/MacOS/Wireshark
  ```

  * if a library is missing (e.g. QtDBus.framework), copy it (must use `ditto` not `cp -r`)

  ```shell
  pushd run/Wireshark.app/Contests/Frameworks
  ditto /opt/homebrew/Cellar/qt/6.6.0/lib/QtDBus.framework QtDBus.framework
  codesign --sign "Apple Development: Fred Klassen (VRZWY3PKS3)" --prefix "org.broadcom.appneta" \
    --entitlements ../packaging/macosx/entitlements.plist --timestamp --verbose -f --deep QtDBus.framework
  popd
  ```

  * if libraries are still missing, it may be easier to install upstream official build and copy those libraries as they have updated @rpath

  ```shell
  pushd run/Wireshark.app/Contests/Frameworks
  ditto /Applications/Wireshark_orig.app/Contents/Frameworks/libdbus.1.3.dylib .
  codesign --sign "Apple Development: Fred Klassen (VRZWY3PKS3)" --prefix "org.broadcom.appneta" \
      --entitlements ../packaging/macosx/entitlements.plist --timestamp --verbose -f libdbus.1.3.dylib
  popd
  ```

* Make a backup copy of `run/Wireshark.app` as the next command will break it

  ```shell
  mkdir -p ~/data
  ditto run/Wireshark.app ~/data/Wireshark.app
  ```

* Make the install `.dmg` file

  ```shell
  cmake --build . --target wireshark_dmg
  ```

* Replace a broken `Wireshark.app` in the dmg bundle with the working one

  ```shell
  pushd run
  hdiutil convert Wireshark\ 4.6.2.appneta.65\ Arm\ 64.dmg -format UDRW -o Wireshark\ 4.6.2.appneta.65\ Arm\ 64-rw.dmg
  hdiutil resize -size 500M  Wireshark\ 4.6.2.appneta.65\ Arm\ 64-rw.dmg
  hdiutil attach Wireshark\ 4.6.2.appneta.65\ Arm\ 64-rw.dmg
  rm -rf /Volumes/Wireshark\ 4.6.2.appneta.65/Wireshark.app
  ditto ~/data/Wireshark.app /Volumes/Wireshark\ 4.6.2.appneta.65/Wireshark.app
  ```

  * At this point you will use Finder to unmount the `.dmg` bundle
  * Now convert R/W bundle to R/O

  ```shell
  hdiutil convert Wireshark\ 4.6.2.appneta.65\ Arm\ 64-rw.dmg -format UDRO -o ~/data/Wireshark\ 4.6.2.appneta.65\ Arm\ 64.dmg
  popd
  ```

* Code sign the new bundle

  ```shell
  codesign --sign "Apple Development: Fred Klassen (VRZWY3PKS3)" --prefix "org.broadcom.appneta" \
    --entitlements ../packaging/macosx/entitlements.plist --timestamp --verbose -f ~/data/Wireshark\ 4.6.2.appneta.65\ Arm\ 64.dmg
  ```

* Test the new installer program
  * At this point the `dmg` should be installable by any developer who has installed their `Apple Development` certificate,
    and is running the same OS version or newer
  * To enable others to install the `dmg` you will need to Notarize (if you have rights to do so)

Notarize - optional (only supported on TC build machines)
---------------------------------------------------------

At this point you may want to notarize the app_bundle - you will require an
application-specific password - <https://support.apple.com/en-us/HT204397>

```shell
cd run
ditto -ck --keepParent Wireshark.app Wireshark.zip
xcrun altool --notarize-app --primary-bundle-id "com.appneta.wireshark.app" --username <apple id> --password <app-specific password> --file Wireshark.zip
```

Wait up to 5 minutes for success - check using this command

```shell
xcrun altool --notarize-history 0 --username <apple id> --password <app-specific password>
```

Staple the notarization result so app can be verified as notarized when offline

```shell
xcrun stapler staple Wireshark.app
cd ..
```

macOS Notarize Package
----------------------

* this probably will break `Wireshark.app` but it is here for reference

```shell
cd run
../packaging/macosx/osx-dmg.sh
xcrun altool --notarize-app --primary-bundle-id "com.appneta.wireshark.dmg" --username <apple id> --password <app-specific password> --file Wireshark\ <version>\ Intel\ 64.dmg
xcrun altool --notarize-history 0 --username <apple id> --password <app-specific password>
xcrun stapler staple Wireshark\ <version>\ Intel\ 64.dmg
cd ..
```

Linux
=====

To build Linux debug
---------------------

```shell
mkdir -p build-debug
cd build-debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j6
```

Make Linux Package
------------------

Install prerequisites

    $ sudo tools/debian-setup.sh --install-all

Build packages (from wireshark directory)

    $ dpkg-buildpackage -b -us -uc -jauto
    $ mkdir -p ~/data/wireshark_4.4.5.appneta.61_repo
    $ mv ../wireshark_4.4.5* ~/data/wireshark-4.4.5-appneta.61_repo

Once packages are made, do something like:

    cd ~/data/wireshark-4.4.5-appneta.61_repo
    dpkg-scanpackages . | xz -c > Packages.xz

Optionally you can move directory and install packages locally
... in /etc/apt/sources.list.d/wireshark.list ... (not working for Debian bookworm)

    deb [trusted=yes] file:/home/fklassen/data/wireshark-4.4.5-appneta-61-repo ./
    $ sudo apt update
    $ sudo apt install wireshark

To manually install, remove any old versions of wireshark and run something like this:

    sudo dpkg -i libwireshark18_4.4.5.appneta.61_arm64.deb libwireshark-data_4.4.5.appneta.61_all.deb libwiretap15_4.4.5.appneta.61_arm64.deb libwsutil16_4.4.5.appneta.61_arm64.deb tshark_4.4.5.appneta.61_arm64.deb wireshark_4.4.5.appneta.61_arm64.deb wireshark-common_4.4.5.appneta.61_arm64.deb  wireshark-dev_4.4.5.appneta.61_arm64.deb wireshark-doc_4.4.5.appneta.61_all.deb

Windows
=======

* Set up as per [install guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html).
  No need to install Git, CMake, Python or Perl on Windows Dev machine. Install Qt5 not Qt6.

* I had to open a regular Command Prompt and run
  `"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"`
  rather than open a "x64 Native Tools Command Prompt for VS 2019".

* Set the following environmental variables e.g.

```
set WIRESHARK_BASE_DIR=C:\Users\fklassen\git
set WIRESHARK_VERSION_EXTRA=-appneta.60
set WIRESHARK_QT6_PREFIX_PATH=C:\Qt\6.8.0\msvc2022_64
```

* Create a build directory and change into it e.g

    > mkdir ..\wsbuild64
    > cd ..\wsbuild64

* Generate build files

     > "C:\Program Files\CMake\bin\cmake" -G "Visual Studio 16 2019" -A x64 ..\wireshark

* Make

    > msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln

