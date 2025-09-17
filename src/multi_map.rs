use std::collections::HashMap;
use std::hash::Hash;

/// `MultiMap` is a hash map that can index an item by two keys. For example,
/// after an item with key `(a, b)` is inserted, `map.get1(a)` and
/// `map.get2(b)` both return the item. Likewise the `remove1` and `remove2`.
pub struct MultiMap<K1, K2, V> {
    map1: HashMap<K1, (K2, V)>,
    map2: HashMap<K2, K1>,
}

#[allow(dead_code)]
impl<K1, K2, V> MultiMap<K1, K2, V>
where
    K1: Eq + Hash + Clone,
    K2: Eq + Hash + Clone,
{
    pub fn new() -> Self {
        MultiMap {
            map1: HashMap::new(),
            map2: HashMap::new(),
        }
    }

    pub fn insert(&mut self, k1: K1, k2: K2, v: V) -> Result<(), (K1, K2, V)> {
        if self.map1.contains_key(&k1) || self.map2.contains_key(&k2) {
            return Err((k1, k2, v));
        }

        self.map1.insert(k1.clone(), (k2.clone(), v));
        self.map2.insert(k2, k1);
        Ok(())
    }

    pub fn get1(&self, k1: &K1) -> Option<&V> {
        self.map1.get(k1).map(|(_, v)| v)
    }

    pub fn get1_mut(&mut self, k1: &K1) -> Option<&mut V> {
        self.map1.get_mut(k1).map(|(_, v)| v)
    }

    pub fn get2(&self, k2: &K2) -> Option<&V> {
        let k1 = self.map2.get(k2)?;
        self.map1.get(k1).map(|(_, v)| v)
    }

    pub fn get_mut2(&mut self, k2: &K2) -> Option<&mut V> {
        let k1 = self.map2.get(k2)?;
        self.map1.get_mut(k1).map(|(_, v)| v)
    }

    pub fn remove1(&mut self, k1: &K1) -> Option<V> {
        if let Some((k2, v)) = self.map1.remove(k1) {
            self.map2.remove(&k2);
            Some(v)
        } else {
            None
        }
    }

    pub fn remove2(&mut self, k2: &K2) -> Option<V> {
        if let Some(k1) = self.map2.remove(k2) {
            self.map1.remove(&k1).map(|(_, v)| v)
        } else {
            None
        }
    }
}
