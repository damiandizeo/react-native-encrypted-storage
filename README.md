# react-native-encrypted-storage

This is a fork of https://github.com/amsterdam-platform-creation/react-native-encrypted-storage.

## What was changed

### Storage options

You can pass a set of **options** as the previous to last parameter of `setItem`, `getItem`, `removeItem` or `clear` functions:

```js
await EncryptedStorage.removeItem('user_session', {
  storageName: 'userStorage',
});
```

The following options are supported:

- `keychainAccessibility` (**iOS only**)

  Control item availability relative to the lock state of the device. If the attribute ends with the string `ThisDeviceOnly`, the item can be restored to the same device that created a backup, but it isn’t migrated when restoring another device’s backup data. [Read more](https://developer.apple.com/documentation/security/keychain_services/keychain_items/restricting_keychain_item_accessibility?language=objc)

  Default value: `kSecAttrAccessibleAfterFirstUnlock`

- `keychainAccessGroup` (**iOS only**)

  A key with a value that’s a string indicating the access group the item is in. [Read more](https://developer.apple.com/documentation/security/ksecattraccessgroup)

- `storageName`

  A string for identifying a set of storage items. Should not contain path separators. Uses [kSecAttrService](https://developer.apple.com/documentation/security/ksecattrservice?language=objc) on iOS and [fileName](https://developer.android.com/reference/kotlin/androidx/security/crypto/EncryptedSharedPreferences?hl=en#create) on Android.

  Default value: App's bundle id

## Collaboration instructions

### Release a new version

1. Bump version in `package.json`
1. Push to `main` branch
1. [ci workflow](.github/workflows/ci.yml) runs
1. A `tag` with the new version is added

You can add this new release to your app's dependencies in `package.json`, using the newly created `tag`:

```json
{
  "dependencies": {
    "react-native-encrypted-storage": "https://github.com/damiandizeo/react-native-encrypted-storage.git"
  }
}
```

> Note: The `lib/` directory contains the compiled library (results from running `yarn build`) and should not be changed directly.
