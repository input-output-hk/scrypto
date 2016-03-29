package scorex.crypto.ads

sealed trait StorageType

object StorageType {
  implicit val mapDb = new MapDbStorageType
  implicit val mvStore = new MvStoreStorageType
}

final class MapDbStorageType extends StorageType

final class MvStoreStorageType extends StorageType
