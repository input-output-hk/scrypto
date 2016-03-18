package scorex.crypto.ads

import java.io.File

import org.mapdb.{DB, DBMaker, HTreeMap}
import scorex.utils.ScryptoLogging

import scala.util.{Failure, Success, Try}

/**
  * Common key-value storage kept in file
  */
class MapDBStorage[Key, Value](fileName: String) extends Storage[Key, Value] with ScryptoLogging {

  protected val db: DB = DBMaker.appendFileDB(new File(fileName))
    .fileMmapEnableIfSupported()
    .closeOnJvmShutdown()
    .checksumEnable()
    .transactionDisable()
    .make()

  protected val map: HTreeMap[Key, Value] = db.hashMapCreate("map").makeOrGet()

  override def set(key: Key, value: Value): Unit =
    Try(map.put(key, value)).recoverWith { case t: Throwable =>
      log.warn("Failed to set key:" + key, t)
      Failure(t)
    }

  override def commit(): Unit = db.commit()

  override def close(): Unit = db.close()

  override def containsKey(key: Key): Boolean = map.containsKey(key)

  override def get(key: Key): Option[Value] =
    Try(map.get(key)) match {
      case Success(v) =>
        Option(v)

      case Failure(e) =>
        log.debug("Enable to get for key: " + key)
        None
    }

}