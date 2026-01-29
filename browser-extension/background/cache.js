export class CacheManager {
  constructor() {
    this.cacheDuration = 3600000; // 1 hour in milliseconds
  }

  async get(url) {
    try {
      const result = await chrome.storage.local.get([url]);
      if (result[url]) {
        const cached = result[url];
        // Check if cache is still valid
        if (Date.now() - cached.timestamp < this.cacheDuration) {
          return cached.data;
        }
        // Cache expired, remove it
        await this.remove(url);
      }
      return null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(url, data) {
    try {
      const cacheEntry = {
        data: data,
        timestamp: Date.now()
      };
      await chrome.storage.local.set({ [url]: cacheEntry });
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  async remove(url) {
    try {
      await chrome.storage.local.remove([url]);
    } catch (error) {
      console.error('Cache remove error:', error);
    }
  }

  async clear() {
    try {
      await chrome.storage.local.clear();
    } catch (error) {
      console.error('Cache clear error:', error);
    }
  }
}
