/* eslint-disable no-dupe-class-members */

import { NativeModules } from 'react-native';
const { RNEncryptedStorage } = NativeModules;

if (!RNEncryptedStorage) {
  throw new Error('RNEncryptedStorage is undefined');
}

export type StorageErrorCallback = (error?: Error) => void;
export type StorageValueCallback = (error?: Error, value?: string) => void;

export default class EncryptedStorage {
  /**
   * Returns true if device has passcode/faceid/touchid set and therefore protects user's data.
   * If this returns false the app should tell user to provide an app-specific password.
   */
   static isDeviceProtected(): Promise<boolean>;

   /**
    * Returns true if device has passcode/faceid/touchid set and therefore protects user's data.
    * @param {Function} cb - The function to call when the operation completes.
    */
  static isDeviceProtected(cb: StorageErrorCallback): void;
  static isDeviceProtected(cb?: StorageErrorCallback): void | Promise<boolean> {
    if (cb) {
      RNEncryptedStorage.isDeviceProtected().then(cb).catch(cb);
      return;
    }
    return RNEncryptedStorage.isDeviceProtected();
  }
 
  /**
   * Writes data to the disk, using SharedPreferences or KeyChain, depending on the platform.
   * @param {string} key - A string that will be associated to the value for later retrieval.
   * @param {string} value - The data to store.
   */
  static setItem(key: string, value: string): Promise<void>;

  /**
   * Writes data to the disk, using SharedPreferences or KeyChain, depending on the platform.
   * @param {string} key - A string that will be associated to the value for later retrieval.
   * @param {string} value - The data to store.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static setItem(key: string, value: string, cb: StorageErrorCallback): void;
  static setItem(
    key: string,
    value: string,
    cb?: StorageErrorCallback
  ): void | Promise<void> {
    if (cb) {
      RNEncryptedStorage.setItem(key, value).then(cb).catch(cb);
      return;
    }

    return RNEncryptedStorage.setItem(key, value);
  }

  /**
   * Retrieves data from the disk, using SharedPreferences or KeyChain, depending on the platform and returns it as the specified type.
   * @param {string} key - A string that is associated to a value.
   */
  static getItem(key: string): Promise<string | null>;

  /**
   * Retrieves data from the disk, using SharedPreferences or KeyChain, depending on the platform and returns it as the specified type.
   * @param {string} key - A string that is associated to a value.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static getItem(key: string, cb: StorageValueCallback): void;
  static getItem(
    key: string,
    cb?: StorageValueCallback
  ): void | Promise<string | null> {
    if (cb) {
      RNEncryptedStorage.getItem(key).then(cb).catch(cb);
      return;
    }

    return RNEncryptedStorage.getItem(key);
  }

  /**
   * Deletes data from the disk, using SharedPreferences or KeyChain, depending on the platform.
   * @param {string} key - A string that is associated to a value.
   */
  static removeItem(key: string): Promise<void>;

  /**
   * Deletes data from the disk, using SharedPreferences or KeyChain, depending on the platform.
   * @param {string} key - A string that is associated to a value.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static removeItem(key: string, cb: StorageErrorCallback): void;
  static removeItem(
    key: string,
    cb?: StorageErrorCallback
  ): void | Promise<void> {
    if (cb) {
      RNEncryptedStorage.removeItem(key).then(cb).catch(cb);
      return;
    }

    return RNEncryptedStorage.removeItem(key);
  }

  /**
   * Clears all data from disk, using SharedPreferences or KeyChain, depending on the platform.
   */
  static clear(): Promise<void>;

  /**
   * Clears all data from disk, using SharedPreferences or KeyChain, depending on the platform.
   * @param {Function} cb - The function to call when the operation completes.
   */
  static clear(cb: StorageErrorCallback): void;
  static clear(cb?: StorageErrorCallback): void | Promise<void> {
    if (cb) {
      RNEncryptedStorage.clear().then(cb).catch(cb);
      return;
    }

    return RNEncryptedStorage.clear();
  }
}
