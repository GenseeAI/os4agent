#ifndef __CR_TIME_NS_H__
#define __CR_TIME_NS_H__

extern int read_time_ns_img(void);
extern void cleanup_time_ns_img(void);

extern int dump_timens_one_task(pid_t pid, int time_ns_id, int time_for_children_ns_id);
extern int prepare_timens_one_task(int time_ns_id, int time_for_children_ns_id);

extern struct ns_desc time_ns_desc;
extern struct ns_desc time_for_children_ns_desc;

#endif /* __CR_TIME_NS_H__ */
