<?php

class Session {

    // allocate 2MB for session usage (approx. 2 million characters)
    const MEMORY_ALLOCATION = 2000000;
    const ID_NAME = 'MEMSESSID';
    const GC_CACHE = '/tmp';

    public function __construct()
    {
        // set all php session handlers to use the functions present within this class
        session_set_save_handler(
            array($this, 'open'),
            array($this, 'close'),
            array($this, 'read'),
            array($this, 'write'),
            array($this, 'destroy'),
            array($this, 'gc')
        );

        // set cookie name and use cookie to keep track of session
        session_name(self::ID_NAME);

        if (isset($_COOKIE[self::ID_NAME]))
        { session_id($_COOKIE[self::ID_NAME]); }

        // set a custom session id as it needs to be set prior to open (initial creation of shared memory allocation)
        else
        {
            $id = substr(md5((openssl_random_pseudo_bytes(17))), 0, 10);
            file_put_contents(self::GC_CACHE . "/{$id}.msid", $id);
            session_id($id);
        }

        // kick off the session start which will call open
        session_start();
    }

    // setup new memory allocated to only this application (for both read and write - 0600)
    // to troubleshoot permissions can be set to 0644 and 'ipcs -m' can be used to see memory allocation
    public function open()
    {
        $resource = shmop_open(bin2hex(session_id()), 'c', 0600, self::MEMORY_ALLOCATION);
        if ($resource === false) return false;
        shmop_close($resource);
        return true;
    }

    // access and close the resourse (no more reads/writes allowed)
    public function close()
    {
        $resource = @shmop_open(bin2hex(session_id()), 'a', 0, 0);
        if ($resource === false) return true;
        shmop_close($resource);
        return true;
    }

    // read data from memory, decompress, and touch msid file to keep track of access time
    public function read($id)
    {
        touch(self::GC_CACHE . "/{$id}.msid");
        $resource = shmop_open(bin2hex($id), 'w', 0, 0);
        if ($resource === false) return '';
        $size = shmop_size($resource);
        $cdata = shmop_read($resource, 0, $size);
        if ($cdata === false || trim($cdata) === '') return '';
        return (string)gzuncompress($cdata);
    }

    // compress data, write to memory, and touch msid file to keep track of access time
    public function write($id, $data)
    {
        touch(self::GC_CACHE . "/{$id}.msid");
        $resource = shmop_open(bin2hex($id), 'w', 0, 0);
        if ($resource === false) return false;
        $cdata = gzcompress($data, 1);
        $size = strlen($cdata);
        $bytes_written = shmop_write($resource, $cdata, 0);
        return $size === $bytes_written ? true : false;
    }

    // unlink msid file as access time is no longer needed and clear memory at this shmid (shared memory id)
    public function destroy($id)
    {
        unlink(self::GC_CACHE . "/{$id}.msid");
        $resource = shmop_open(bin2hex($id), 'w', 0, 0);
        if ($resource === false) return true;
        return shmop_delete($resource) === false ? false : true;
    }

    // garbage collection should loop through all the msid files checking access times and destroy where needed
    public function gc($max_life)
    {
        foreach (glob(self::GC_CACHE . '/*.msid') as $msid)
        {
            $session_id = file_get_contents($msid);
            $last_access = fileatime($msid);
            if ($last_access === false) continue;
            if (time() > ($last_access + $max_life))
            { $this -> destroy($session_id); }
        }
        return true;
    }
}
