#-  persistance module for Berry -#
#- -#
#- To solidify: -#
#-
  # load only persist_module and persist_module.init
  import solidify
  solidify.dump(persist_module.init)
  # copy and paste into `be_persist_lib.c`
-#
#@ solidify:persist_module
var persist_module = module("persist")

class Persist
  static var _filename = '_persist.json'
  static var _tmpname = '_persist.tmp'      # a save writes here, and moves it over the file only when it is whole
  static var _badname = '_persist.bad'      # a file that load() could not use, put aside so that the next save does not cover it
  var _p
  var _dirty

  def init()
    self._p = {}
    self._dirty = false
    self.load()
  end

  #- virtual member getter, if a key does not exists return `nil` instead of exception -#
  def member(key)
    return self._p.find(key)
  end

  #- virtual member setter -#
  def setmember(key, value)
    self._p[key] = value
    self._dirty = true
  end

  #- clear all entries -#
  def zero()
    self._p = {}
    self._dirty = true
  end
  
  #- force dirty -#
  def dirty()
    self._dirty = true
  end

  def remove(k)
      self._p.remove(k)
      self._dirty = true
  end

  def contains(k)
      return self._p.contains(k)
  end

  def has(k)      # deprecated, use contains instead
    return self._p.contains(k)
  end

  def find(k, d)
      return self._p.find(k, d)
  end

  def load()
    import json
    import path
    var f           # file object
    var val         # values loaded from json
    var name = self._filename

    # A save that was cut off after it took the old file away and before it put the new one in its place leaves the new one, whole
    # when it was closed, in the temp file: that is the file
    if !path.exists(name) && path.exists(self._tmpname)
      name = self._tmpname
    end

    if path.exists(name)
      try
        f = open(name, "r")
        val = json.load(f.read())
        f.close()
      except .. as e, m
        if f != nil f.close() end
        raise e, m
      end
      if isinstance(val, map)
        self._p = val     # success
        if name != self._filename
          # the cut-off save is finished (rename, unlike open() and the others, wants the '/' in front of a name)
          path.rename('/' + name, '/' + self._filename)
        end
      else
        # What the file holds is no map, or no JSON: it is put aside, as _persist.bad, so that the next save, which would cover it
        # with a persist that starts from nothing, does not destroy it
        path.remove(self._badname)
        path.rename('/' + name, '/' + self._badname)
        print("BRY: failed to load _persist.json, kept as _persist.bad")
      end
      self._dirty = false
    else
      self.save()
    end

    # print("Loading")
  end

  def save(force_save)
    if self._dirty || force_save   # do not save if not dirty
      import path
      var f       # file object
      # The file is never opened for writing: the new one is written whole in the temp file and closed, and only then takes the old
      # one's place. A write that fails, or a power cut while it goes, leaves the file that was there, the last whole one, and the
      # map in memory is still dirty, so the next save writes it all again. The empty map that used to be written when a save failed
      # is gone with the file it destroyed
      try
        f = open(self._tmpname, "w")
        self.json_fdump(f)
        f.close()
        f = nil
      except .. as e, m
        if (f != nil) f.close() end
        f = nil
        path.remove(self._tmpname)
        raise e, m
      end
      path.remove(self._filename)
      if !path.rename('/' + self._tmpname, '/' + self._filename)
        raise "io_error", "persist: could not move the new file over _persist.json"
      end
      self._dirty = false
    end
  end

  def json_fdump_any(f, v)
    import json
    if   isinstance(v, map)
      self.json_fdump_map(f, v)
    elif isinstance(v, list)
      self.json_fdump_list(f, v)
    else
      f.write(json.dump(v))
    end
  end

  def json_fdump_map(f, v)
    import json
    f.write('{')
    var sep = nil
    for k:v.keys()
      if sep != nil  f.write(sep) end
      
      f.write(json.dump(str(k)))
      f.write(':')
      self.json_fdump_any(f, v[k])

      sep = ","
    end
    f.write('}')
  end

  def json_fdump_list(f, v)
    import json
    f.write('[')
    var i = 0
    while i < size(v)
      if i > 0   f.write(',') end
      self.json_fdump_any(f, v[i])
      i += 1
    end
    f.write(']')
  end

  def json_fdump(f)
    import json
    if isinstance(self._p, map)
      self.json_fdump_map(f, self._p)
    else
      raise "internal_error", "persist._p is not a map"
    end
  end
end
persist_module.Persist = Persist

persist_module.init = def (m)
  return m.Persist()    # return an instance of this class
end

return persist_module
