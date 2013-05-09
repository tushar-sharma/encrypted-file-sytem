/* This file deals with protection in the file system.  It contains the code
 * for four system calls that relate to protection.
 *
 * The entry points into this file are
 *   do_chmod:    perform the CHMOD and FCHMOD system calls
 *   do_chown:    perform the CHOWN and FCHOWN system calls
 *   do_umask:    perform the UMASK system call
 *   do_access:    perform the ACCESS system call
 */
//Modified 6.6


#include "fs.h"
#include <sys/stat.h>
#include <unistd.h>
#include <minix/callnr.h>
#include "file.h"
#include "fproc.h"
#include "path.h"
#include "param.h"
#include <minix/vfsif.h>
#include "vnode.h"
#include "vmnt.h"
#include <stdio.h>
#include <string.h>

typedef struct
{
    dev_t dev; //device no
    ino_t inode;
    char hash_pw[65];
}MET;

#define BASE_CHAR 0
#define MAX_CHAR 255
#define MAX_KEY_LENGTH 65
#define ENCRYPTED_FILE_TABLE "/etc/MET"
#define ENCRYPTED_FILE_TABLE_KEY "rose"
#define INVALID_INODE -1 //Used for deleting entries from the table
#define BUFFER_SIZE 256

MET node1, node2;

char mybuffer[BUFFER_SIZE];

/*  write_to_MET */

int write_to_MET()
{
  char *fullpath = "/etc/MET";
  struct lookup resolve;
  struct vmnt *vmp;
  struct vnode *vp;
  int r;
  u64_t new_pos;
  unsigned int cum_iop;

  /*if (sys_datacopy(who_e, (vir_bytes) m_in.m7_p1, VFS_PROC_NR, (vir_bytes) fullpath, (phys_bytes) m_in.m7_i2) != OK)
     return(err_code);
*/

  lookup_init(&resolve, fullpath, PATH_NOFLAGS, &vmp, &vp);
  resolve.l_vmnt_lock = VMNT_WRITE;
  resolve.l_vnode_lock = VNODE_WRITE;

  if((vp = eat_path(&resolve, fp)) == NULL)
      return(err_code);

  //r = req_readwrite(vp->v_fs_e, vp->v_inode_nr,vp->v_size, WRITING, fproc[VFS_PROC_NR].fp_endpoint,  (char *)&node, sizeof(MET), &new_pos, &cum_iop);

  r = req_readwrite(vp->v_fs_e, vp->v_inode_nr,vp->v_size, WRITING, fproc[VFS_PROC_NR].fp_endpoint,  (char *)&node1, sizeof(node1), &new_pos, &cum_iop);


  //printf("%u\n",met_object.dev);
  //printf("%lu\n", met_object.inode);

   unlock_vnode(vp);
   if(vmp != NULL)
      unlock_vmnt(vmp);
     put_vnode(vp);

   return OK;
}

long get_file_size(const char *filepath)
{
    struct vnode *vp;
    struct vmnt *vmp;
    struct lookup resolve;

    lookup_init(&resolve, (char *)filepath, PATH_NOFLAGS, &vmp, &vp);

    resolve.l_vmnt_lock = VMNT_READ;
    resolve.l_vnode_lock = VNODE_OPCL;

    if ((vp = eat_path(&resolve, fp)) == NULL)
        printf("Unable to retreive inode!\n");

    long fileSize = -1;

    if (vp) {
        unlock_vnode(vp);
        unlock_vmnt(vmp);
        put_vnode(vp);
        fileSize = vp->v_size;
    }

    return fileSize;
}


int write_to_file(u64_t post, u64_t *newPos, char *fullpath2)
{
    //rintf(" some text %s \n", fullpath1);


	/*char *fullpath2 = "/usr/src/project3/testFile.txt";

	printf(" sudo testing %s\n", fullpath2);
    */

    int r;
    struct vnode* vp;
    struct vmnt *vmp;
    struct lookup resolve;
    unsigned int cum_iop;

    //Initialize the lookup routines
    lookup_init(&resolve, fullpath2, PATH_NOFLAGS, &vmp, &vp);
    resolve.l_vmnt_lock  = VMNT_READ;
    resolve.l_vnode_lock = VNODE_READ;

    //Retrieve the vp for the system ACL
    if ((vp = eat_path(&resolve, fp)) == NULL)
    return err_code;

    //Update MET entry or Append new MET entry to end
    r = req_readwrite(vp->v_fs_e, vp->v_inode_nr,
                    post, WRITING,
                    fproc[VFS_PROC_NR].fp_endpoint,
                    (char*)mybuffer, sizeof(mybuffer),
                    newPos, &cum_iop);

    //unlock and return any resources we acquired
    unlock_vnode(vp);
    if (vmp != NULL)
        unlock_vmnt(vmp);
    put_vnode(vp);
    return r;
}



int read_e_record(MET *write, u64_t post, u64_t *newPos, char *filepath)
{
    int r;
    struct vnode* vp;
    struct vmnt *vmp;
    struct lookup resolve;
    unsigned int cum_iop;

    //Initialize the lookup routines
    lookup_init(&resolve, filepath, PATH_NOFLAGS, &vmp, &vp);
    resolve.l_vmnt_lock  = VMNT_READ;
    resolve.l_vnode_lock = VNODE_READ;

    //Retrieve the vp for the system ACL
    if ((vp = eat_path(&resolve, fp)) == NULL)
    return err_code;

    //Update MET entry or Append new MET entry to end
    r = req_readwrite(vp->v_fs_e, vp->v_inode_nr,
                    post, READING,
                    fproc[VFS_PROC_NR].fp_endpoint,
                    (char*)write, sizeof(MET),
                    newPos, &cum_iop);

    //unlock and return any resources we acquired
    unlock_vnode(vp);
    if (vmp != NULL)
        unlock_vmnt(vmp);
    put_vnode(vp);

    return r;
}



int read_e_record1(u64_t post, u64_t *newPos, char *fullpath3)
{
    //post = 0;
    //newPos = 0;

	//char *fullpath1 = "/usr/src/project3/testFile.txt";

	//printf(" new path %s\n", fullpath1);

    int r;
    struct vnode* vp;
    struct vmnt *vmp;
    struct lookup resolve;
    unsigned int cum_iop;

    //Initialize the lookup routines
    lookup_init(&resolve, fullpath3, PATH_NOFLAGS, &vmp, &vp);
    resolve.l_vmnt_lock  = VMNT_READ;
    resolve.l_vnode_lock = VNODE_READ;

    //Retrieve the vp for the system ACL
    if ((vp = eat_path(&resolve, fp)) == NULL)
    return err_code;

    //Update MET entry or Append new MET entry to end
    r = req_readwrite(vp->v_fs_e, vp->v_inode_nr,
                    post, READING,
                    fproc[VFS_PROC_NR].fp_endpoint,
                    (char*)mybuffer, sizeof(mybuffer),
                    newPos, &cum_iop);

    //unlock and return any resources we acquired
    unlock_vnode(vp);
    if (vmp != NULL)
        unlock_vmnt(vmp);
    put_vnode(vp);
    return r;

}


int do_myencrypt()
{
   //get_local_file();

   //write_to_MET();
    char fullpath[PATH_MAX];
    char key[MAX_KEY_LENGTH];
    char fullpath1[PATH_MAX];
    char fullpath2[PATH_MAX];
    char fullpath3[PATH_MAX];

    int check_mode = m_in.m7_i1;

    if (sys_datacopy(who_e, (vir_bytes) m_in.m7_p1, VFS_PROC_NR, (vir_bytes) fullpath, (phys_bytes) m_in.m7_i2) != OK)
          return err_code;

    if (sys_datacopy(who_e, (vir_bytes) m_in.m7_p2, VFS_PROC_NR, (vir_bytes) key, (phys_bytes) m_in.m7_i3) != OK)
          return err_code;

    strcpy(fullpath1, fullpath);
    strcpy(fullpath2, fullpath);
    strcpy(fullpath3, fullpath);

    //printf(" full path 1.2 %s", fullpath);
    //MET node1;

    struct lookup resolve;
    struct vmnt *vmp;
    struct vnode *vp;
   // u64_t pos = 0;
    //u64_t new_pos;
    //unsigned int cum_iop;


    lookup_init(&resolve, (char *)fullpath, PATH_NOFLAGS, &vmp, &vp);

    resolve.l_vmnt_lock = VMNT_READ;
    resolve.l_vnode_lock = VNODE_READ;

    if ((vp = eat_path(&resolve, fp)) == NULL)
        return err_code;

    node1.inode = vp->v_inode_nr;
    node1.dev = vp->v_dev;
    strcpy(node1.hash_pw, key);
    printf("Inode number %lu\n", node1.inode);
    printf("Device number %u\n", node1.dev);
    printf("Password passed %s\n", node1.hash_pw);

    unlock_vnode(vp);
    if(vmp != NULL)
        unlock_vmnt(vmp);
    put_vnode(vp);


  long table_entries = get_file_size(ENCRYPTED_FILE_TABLE) / sizeof(MET);

  //MET node2 ;
  u64_t currentPos = 0; //Start at the beginning of the file
  u64_t newPos;
  int check = 0;

  for (int i = 0; i < table_entries; i++) {

      if (read_e_record(&node2, currentPos, &newPos, ENCRYPTED_FILE_TABLE) != OK)
      {
          printf("An error occured when reading the encrypted table file.\n");
          return -1; //Denotes an error
      }
      //printf("  testing %s\n", node2.hash_pw);
      if ( (node1.dev == node2.dev) && (node1.inode == node2.inode)) {
          check = 1;
          break;
      }

      currentPos = newPos;
  }

  if (check == 0)
      write_to_MET();
  else
      printf("\nFile already encrypted\n");



 //Now print the content of the file

  //printf(" full path new %s\n", fullpath1);
  long file_size = get_file_size(fullpath1);

  currentPos = 0;
  u64_t newPos1;
  for (int i = 0; i < file_size;i += BUFFER_SIZE) {
	  if (read_e_record1(currentPos, &newPos1, fullpath3) != OK){
	            printf("An error occured when reading the user text file.\n");
	            return -1; //Denotes an error
	  }
	  //printf("%s \n", mybuffer);
  }


  //write to a file
  //we have fullpath2
 //for encryption

  if (check_mode == 1) { //for encryption
      for (int j = 0; j < strlen(mybuffer); j++) {
      		mybuffer[j] =mybuffer[j] + 1;
      	}
  }
  else {  //for decryption
      for (int j = 0; j < strlen(mybuffer); j++) {
      		mybuffer[j] =mybuffer[j] - 1;
      	}
  }
  //printf(" %s\n", mybuffer);

    currentPos = 0;
    u64_t newPos2;

    for (int i = 0; i < file_size;i += BUFFER_SIZE) {

  	  if (write_to_file(currentPos, &newPos2, fullpath2) != OK){
  	            printf("An error occured when reading the user text file.\n");
  	            return -1; //Denotes an error
  	  }
    }


    /*unlock_vnode(vp);
     if(vmp != NULL)
         unlock_vmnt(vmp);
     put_vnode(vp);
     */

  //printf(" The size is %ld \n", table_entries);

  //read_from_MET();
  //find_MET(inode_nr, m_in.m7_i1, m_in.m7_i2, &node);

  /*char fullpath[PATH_MAX];
  struct lookup resolve;
  struct vmnt *vmp;
  struct vnode *vp;
  int r = OK;
  u64_t pos = 0;
  u64_t new_pos;
  unsigned int cum_iop;
   */
  //printf("%s\n", m_in.m7_p1);

  //char *ptr = m_in.m7_p1;

  //printf("%d\n", m_in.m7_i1);

  /*if (sys_datacopy(who_e, (vir_bytes) m_in.m7_p1, VFS_PROC_NR, (vir_bytes) fullpath, (phys_bytes) m_in.m7_i1) != OK)
      return err_code;

  //printf("%s\n", fullpath);

  //Temporaray open the file
  */
  /*if(fetch_name((vir_bytes)m_in.m7_p1, m_in.m7_i1, fullpath) != OK)
       return(err_code);
   */

  /*lookup_init(&resolve, fullpath, PATH_NOFLAGS, &vmp, &vp);
  resolve.l_vmnt_lock = VMNT_WRITE;
  resolve.l_vnode_lock = VNODE_WRITE;

  if((vp = eat_path(&resolve, fp)) == NULL)
      return(err_code);


   while (pos < vp->v_size && r == OK) {
        r = req_readwrite(vp->v_fs_e, vp->v_inode_nr, pos, READING, fproc[VFS_PROC_NR].fp_endpoint, (char *) found, sizeof(MET), &new_pos, &cum_iop);

        if (r == OK && found->inode == inode && found->id == id && found->type == type) {
        found ->offset = pos;
        break;
    }
    pos = new_pos;
}

   unlock_vnode(vp);
   if(vmp != NULL)
      unlock_vmnt(vmp);
   put_vnode(vp);

   //printf("%lu\n", vp->v_inode_nr);

   //put_vnode(vp);
   //printf("Hello, world!\n");

   // r = read_only(vp);
   */

   return 0;
}

/*===========================================================================*
 *                do_chmod                     *
 *===========================================================================*/
int do_chmod()
{
/* Perform the chmod(name, mode) and fchmod(fd, mode) system calls.
 * syscall might provide 'name' embedded in the message.
 */

  struct filp *flp;
  struct vnode *vp;
  struct vmnt *vmp;
  int r, rfd;
  mode_t result_mode;
  char fullpath[PATH_MAX];
  struct lookup resolve;
  vir_bytes vname;
  size_t vname_length;
  mode_t new_mode;

  flp = NULL;
  vname = (vir_bytes) job_m_in.name;
  vname_length = (size_t) job_m_in.name_length;
  rfd = job_m_in.fd;
  new_mode = (mode_t) job_m_in.mode;

  lookup_init(&resolve, fullpath, PATH_NOFLAGS, &vmp, &vp);
  resolve.l_vmnt_lock = VMNT_WRITE;
  resolve.l_vnode_lock = VNODE_WRITE;

  if (job_call_nr == CHMOD) {
    /* Temporarily open the file */
    if (copy_name(vname_length, fullpath) != OK) {
        /* Direct copy failed, try fetching from user space */
        if (fetch_name(vname, vname_length, fullpath) != OK)
            return(err_code);
    }
    if ((vp = eat_path(&resolve, fp)) == NULL) return(err_code);
  } else {    /* call_nr == FCHMOD */
    /* File is already opened; get a pointer to vnode from filp. */
    if ((flp = get_filp(rfd, VNODE_WRITE)) == NULL) return(err_code);
    vp = flp->filp_vno;
    dup_vnode(vp);
  }

  /* Only the owner or the super_user may change the mode of a file.
   * No one may change the mode of a file on a read-only file system.
   */
  if (vp->v_uid != fp->fp_effuid && fp->fp_effuid != SU_UID)
    r = EPERM;
  else
    r = read_only(vp);

  if (r == OK) {
    /* Now make the change. Clear setgid bit if file is not in caller's
     * group */
    if (fp->fp_effuid != SU_UID && vp->v_gid != fp->fp_effgid)
        new_mode &= ~I_SET_GID_BIT;

    r = req_chmod(vp->v_fs_e, vp->v_inode_nr, new_mode, &result_mode);
    if (r == OK)
        vp->v_mode = result_mode;
  }

  if (job_call_nr == CHMOD) {
    unlock_vnode(vp);
    unlock_vmnt(vmp);
  } else {    /* FCHMOD */
    unlock_filp(flp);
  }

  put_vnode(vp);
  return(r);
}


/*===========================================================================*
 *                do_chown                     *
 *===========================================================================*/
int do_chown()
{
/* Perform the chown(path, owner, group) and fchmod(fd, owner, group) system
 * calls. */
  struct filp *flp;
  struct vnode *vp;
  struct vmnt *vmp;
  int r, rfd;
  uid_t uid, new_uid;
  gid_t gid, new_gid;
  mode_t new_mode;
  char fullpath[PATH_MAX];
  struct lookup resolve;
  vir_bytes vname1;
  size_t vname1_length;

  flp = NULL;
  vname1 = (vir_bytes) job_m_in.name1;
  vname1_length = (size_t) job_m_in.name1_length;
  rfd = job_m_in.fd;
  uid = job_m_in.owner;
  gid = job_m_in.group;

  lookup_init(&resolve, fullpath, PATH_NOFLAGS, &vmp, &vp);
  resolve.l_vmnt_lock = VMNT_WRITE;
  resolve.l_vnode_lock = VNODE_WRITE;

  if (job_call_nr == CHOWN) {
    /* Temporarily open the file. */
    if (fetch_name(vname1, vname1_length, fullpath) != OK)
        return(err_code);
    if ((vp = eat_path(&resolve, fp)) == NULL) return(err_code);
  } else {    /* call_nr == FCHOWN */
    /* File is already opened; get a pointer to the vnode from filp. */
    if ((flp = get_filp(rfd, VNODE_WRITE)) == NULL)
        return(err_code);
    vp = flp->filp_vno;
    dup_vnode(vp);
  }

  r = read_only(vp);
  if (r == OK) {
    /* FS is R/W. Whether call is allowed depends on ownership, etc. */
    /* The super user can do anything, so check permissions only if we're
       a regular user. */
    if (fp->fp_effuid != SU_UID) {
        /* Regular users can only change groups of their own files. */
        if (vp->v_uid != fp->fp_effuid) r = EPERM;
        if (vp->v_uid != uid) r = EPERM;    /* no giving away */
        if (fp->fp_effgid != gid) r = EPERM;
    }
  }

  if (r == OK) {
    /* Do not change uid/gid if new uid/gid is -1. */
    new_uid = (uid == (uid_t)-1 ? vp->v_uid : uid);
    new_gid = (gid == (gid_t)-1 ? vp->v_gid : gid);

    if (new_uid > UID_MAX || new_gid > GID_MAX)
        r = EINVAL;
    else if ((r = req_chown(vp->v_fs_e, vp->v_inode_nr, new_uid, new_gid,
                &new_mode)) == OK) {
        vp->v_uid = new_uid;
        vp->v_gid = new_gid;
        vp->v_mode = new_mode;
    }
  }

  if (job_call_nr == CHOWN) {
    unlock_vnode(vp);
    unlock_vmnt(vmp);
  } else {    /* FCHOWN */
    unlock_filp(flp);
  }

  put_vnode(vp);
  return(r);
}

/*===========================================================================*
 *                do_umask                     *
 *===========================================================================*/
int do_umask()
{
/* Perform the umask(co_mode) system call. */
  mode_t complement, new_umask;

  new_umask = job_m_in.co_mode;

  complement = ~fp->fp_umask;    /* set 'r' to complement of old mask */
  fp->fp_umask = ~(new_umask & RWX_MODES);
  return(complement);        /* return complement of old mask */
}


/*===========================================================================*
 *                do_access                     *
 *===========================================================================*/
int do_access()
{
/* Perform the access(name, mode) system call.
 * syscall might provide 'name' embedded in the message.
 */
  int r;
  struct vnode *vp;
  struct vmnt *vmp;
  char fullpath[PATH_MAX];
  struct lookup resolve;
  vir_bytes vname;
  size_t vname_length;
  mode_t access;

  vname = (vir_bytes) job_m_in.name;
  vname_length = (size_t) job_m_in.name_length;
  access = job_m_in.mode;

  lookup_init(&resolve, fullpath, PATH_NOFLAGS, &vmp, &vp);
  resolve.l_vmnt_lock = VMNT_READ;
  resolve.l_vnode_lock = VNODE_READ;

  /* First check to see if the mode is correct. */
  if ( (access & ~(R_OK | W_OK | X_OK)) != 0 && access != F_OK)
    return(EINVAL);

  /* Temporarily open the file. */
  if (copy_name(vname_length, fullpath) != OK) {
    /* Direct copy failed, try fetching from user space */
    if (fetch_name(vname, vname_length, fullpath) != OK)
        return(err_code);
  }
  if ((vp = eat_path(&resolve, fp)) == NULL) return(err_code);

  r = forbidden(fp, vp, access);

  unlock_vnode(vp);
  unlock_vmnt(vmp);

  put_vnode(vp);
  return(r);
}


/*===========================================================================*
 *                forbidden                     *
 *===========================================================================*/
int forbidden(struct fproc *rfp, struct vnode *vp, mode_t access_desired)
{
/* Given a pointer to an vnode, 'vp', and the access desired, determine
 * if the access is allowed, and if not why not.  The routine looks up the
 * caller's uid in the 'fproc' table.  If access is allowed, OK is returned
 * if it is forbidden, EACCES is returned.
 */

  register mode_t bits, perm_bits;
  uid_t uid;
  gid_t gid;
  int r, shift;

  if (vp->v_uid == (uid_t) -1 || vp->v_gid == (gid_t) -1) return(EACCES);

  /* Isolate the relevant rwx bits from the mode. */
  bits = vp->v_mode;
  uid = (job_call_nr == ACCESS ? rfp->fp_realuid : rfp->fp_effuid);
  gid = (job_call_nr == ACCESS ? rfp->fp_realgid : rfp->fp_effgid);

  if (uid == SU_UID) {
    /* Grant read and write permission.  Grant search permission for
     * directories.  Grant execute permission (for non-directories) if
     * and only if one of the 'X' bits is set.
     */
    if ( S_ISDIR(bits) || bits & ((X_BIT << 6) | (X_BIT << 3) | X_BIT))
        perm_bits = R_BIT | W_BIT | X_BIT;
    else
        perm_bits = R_BIT | W_BIT;
  } else {
    if (uid == vp->v_uid) shift = 6;        /* owner */
    else if (gid == vp->v_gid) shift = 3;        /* group */
    else if (in_group(fp, vp->v_gid) == OK) shift = 3; /* suppl. groups */
    else shift = 0;                    /* other */
    perm_bits = (bits >> shift) & (R_BIT | W_BIT | X_BIT);
  }

  /* If access desired is not a subset of what is allowed, it is refused. */
  r = OK;
  if ((perm_bits | access_desired) != perm_bits) r = EACCES;

  /* Check to see if someone is trying to write on a file system that is
   * mounted read-only.
   */
  if (r == OK)
    if (access_desired & W_BIT)
        r = read_only(vp);

  return(r);
}

/*===========================================================================*
 *                read_only                     *
 *===========================================================================*/
int read_only(vp)
struct vnode *vp;        /* ptr to inode whose file sys is to be cked */
{
/* Check to see if the file system on which the inode 'ip' resides is mounted
 * read only.  If so, return EROFS, else return OK.
 */
  return((vp->v_vmnt->m_flags & VMNT_READONLY) ? EROFS : OK);
}
