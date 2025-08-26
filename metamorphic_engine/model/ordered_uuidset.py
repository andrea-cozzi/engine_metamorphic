from typing import Dict, List, Iterator, TypeVar, Generic, Protocol, Optional

# Protocollo: qualsiasi oggetto che abbia un attributo/metodo uuid -> str
class HasUUID(Protocol):
    @property
    def uuid(self) -> str: ...


T = TypeVar("T", bound=HasUUID)


class OrderedUUIDSet(Generic[T]):
    def __init__(self) -> None:
        self._order: List[str] = []
        self._items: Dict[str, T] = {}

    def add(self, item: T) -> None:
        """Aggiunge un item in fondo, se non esiste già"""
        uid = item.uuid
        if uid not in self._items:
            self._order.append(uid)
            self._items[uid] = item

    def add_after(self, after_uuid: str, item: T) -> None:
        """Aggiunge un item subito dopo l'elemento con uuid `after_uuid`"""
        uid = item.uuid
        if uid in self._items:
            return  # già presente, non facciamo nulla

        try:
            index = self._order.index(after_uuid)
        except ValueError:
            raise ValueError(f"UUID {after_uuid} non trovato nella sequenza")

        self._order.insert(index + 1, uid)
        self._items[uid] = item

    def swap(self, uuid1: str, uuid2: str) -> None:
        """Scambia di posizione due elementi nella sequenza"""
        if uuid1 == uuid2:
            return
        try:
            index1 = self._order.index(uuid1)
            index2 = self._order.index(uuid2)
        except ValueError as e:
            raise ValueError(f"Uno degli UUID non è stato trovato nel set: {e}")

        self._order[index1], self._order[index2] = self._order[index2], self._order[index1]

    def get_next_from_items(self, current_item_uuid: str, max_distance: int) -> List[T]:
        """
        Restituisce fino a `max_distance` elementi successivi all'elemento con uuid dato.
        """
        try:
            index = self._order.index(current_item_uuid)
        except ValueError:
            raise ValueError(f"UUID {current_item_uuid} non trovato nella sequenza")

        next_uuids = self._order[index + 1 : index + 1 + max_distance]
        return [self._items[uid] for uid in next_uuids]

    def get_prev_from_items(self, current_item_uuid: str, max_distance: int) -> List[T]:
        """
        Restituisce fino a `max_distance` elementi precedenti all'elemento con uuid dato.
        L'ordine restituito è dallo più vicino al più lontano (coerente con il verso della lista).
        """
        try:
            index = self._order.index(current_item_uuid)
        except ValueError:
            raise ValueError(f"UUID {current_item_uuid} non trovato nella sequenza")

        start = max(0, index - max_distance)
        prev_uuids = self._order[start:index]
        return [self._items[uid] for uid in prev_uuids]

    def remove(self, current_item_uuid: str) -> bool:
        """
        Rimuove l'elemento corrispondente a `current_item_uuid`.
        Restituisce True se l'elemento è stato rimosso, False se non esisteva.
        """
        if current_item_uuid not in self._items:
            return False
        self._order.remove(current_item_uuid)
        del self._items[current_item_uuid]
        return True
    
    def add_after_remove(self, after_uuid: str, item: T) -> None:
        """
        Aggiunge `item` subito dopo `after_uuid`.
        Se un elemento con lo stesso UUID di `item` esiste già altrove, lo rimuove.
        """
        uid = item.uuid

        # Rimuove eventuale duplicato
        if uid in self._items:
            self.remove(uid)

        # Aggiunge dopo after_uuid
        self.add_after(after_uuid, item)

        

    def index(self, item: T) -> int:
        """
        Restituisce l'indice dell'item nella sequenza.
        Solleva ValueError se l'item non è presente.
        """
        uid = item.uuid
        try:
            return self._order.index(uid)
        except ValueError:
            raise ValueError(f"Item con uuid {uid} non trovato nella sequenza")
        
    def first(self) -> Optional[T]:
        """Restituisce il primo elemento, oppure None se vuoto"""
        if not self._order:
            return None
        return self._items[self._order[0]]

    def last(self) -> Optional[T]:
        """Restituisce l’ultimo elemento, oppure None se vuoto"""
        if not self._order:
            return None
        return self._items[self._order[-1]]


    def __iter__(self) -> Iterator[T]:
        for uid in self._order:
            yield self._items[uid]

    def __len__(self) -> int:
        return len(self._order)

    def __contains__(self, item: T) -> bool:
        return item.uuid in self._items

    def get_by_uuid(self, uid: str) -> Optional[T]:
        """Restituisce l'oggetto con uuid dato, oppure solleva KeyError se non esiste"""
        return self._items[uid]

    def __getitem__(self, index: int) -> T:
        """Ritorna l'elemento in posizione index"""
        uid = self._order[index]
        return self._items[uid]
    def __setitem__(self, index: int, value: T) -> None:
        """Sostituisce l'elemento in posizione index con un nuovo valore"""
        old_uid = self._order[index]
        new_uid = value.uuid

        # Se il nuovo uuid già esiste ma non è lo stesso slot → errore
        if new_uid in self._items and new_uid != old_uid:
            raise ValueError(f"UUID {new_uid} già presente in OrderedUUIDSet")

        # Aggiorna ordine
        self._order[index] = new_uid

        # Rimuovi il vecchio dalla mappa se cambia uuid
        if old_uid != new_uid:
            del self._items[old_uid]

        # Inserisci/aggiorna il nuovo
        self._items[new_uid] = value

