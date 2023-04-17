use super::{BlockDevice, BLOCK_SZ};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use lazy_static::*;
use up::UPIntrFreeCell;
// use spin::Mutex;

pub struct BlockCache {
    cache: Vec<u8>,
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    modified: bool,
}

impl BlockCache {
    /// Load a new BlockCache from disk.
    pub fn new(block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self {
        // for alignment and move effciency
        let mut cache = vec![0u8; BLOCK_SZ];
        block_device.read_block(block_id, &mut cache);
        Self {
            cache,
            block_id,
            block_device,
            modified: false,
        }
    }

    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }

    pub fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    pub fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= BLOCK_SZ);
        self.modified = true;
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }

    pub fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        f(self.get_ref(offset))
    }

    pub fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        f(self.get_mut(offset))
    }

    pub fn sync(&mut self) {
        if self.modified {
            self.modified = false;
            self.block_device.write_block(self.block_id, &self.cache);
        }
    }
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        self.sync()
    }
}

const BLOCK_CACHE_SIZE: usize = 16;

pub struct BlockCacheManager {
    queue: VecDeque<(usize, Arc<UPIntrFreeCell<BlockCache>>)>,
}

impl BlockCacheManager {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

lazy_static! {
    pub static ref BLOCK_CACHE_MANAGER: UPIntrFreeCell<BlockCacheManager> =
        unsafe { UPIntrFreeCell::new(BlockCacheManager::new()) };
}

pub fn get_block_cache(
    block_id: usize,
    block_device: Arc<dyn BlockDevice>,
) -> Arc<UPIntrFreeCell<BlockCache>> {
    let manager = BLOCK_CACHE_MANAGER.exclusive_access();
    if let Some(pair) = manager.queue.iter().find(|pair| pair.0 == block_id) {
        return Arc::clone(&pair.1);
    }

    // load block into mem and push back
    // may need schedule!
    drop(manager);
    let block_cache = Arc::new(unsafe {
        UPIntrFreeCell::new(BlockCache::new(block_id, Arc::clone(&block_device)))
    });

    let mut manager = BLOCK_CACHE_MANAGER.exclusive_access();
    if manager.queue.len() == BLOCK_CACHE_SIZE {
        // from front to tail
        if let Some((idx, _)) = manager
            .queue
            .iter()
            .enumerate()
            .find(|(_, pair)| Arc::strong_count(&pair.1) == 1)
        {
            manager.queue.drain(idx..=idx);
        } else {
            panic!("Run out of BlockCache!");
        }
    }
    manager.queue.push_back((block_id, Arc::clone(&block_cache)));
    block_cache
}

pub fn block_cache_sync_all() {
    let mut need_sync = Vec::new();
    for (idx, cache) in BLOCK_CACHE_MANAGER.exclusive_access().queue.iter() {
        let mut cache = cache.exclusive_access();
        if cache.modified {
            cache.modified = false;
            need_sync.push(*idx);
        }
    }

    for cache_idx in need_sync {
        let manager = BLOCK_CACHE_MANAGER.exclusive_access();
        let cache = manager.queue.get(cache_idx).unwrap().1.exclusive_access();
        let block_device = cache.block_device.clone();
        let block_id  = cache.block_id;
        // TODO: too heavy
        let block_data = cache.cache.clone();

        // may need schedule!
        drop(cache);
        drop(manager);
        block_device.write_block(block_id, &block_data);
    }
}