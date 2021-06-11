package proxy

import (
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"sync"
)

//var sessionMap = make(map[string]Session)
//var lock = new(sync.RWMutex)

var sessMap = newSessionManager()

//type Session interface {
//	SessionID() string
//	Terminate()
//}

func HandleSessionTask(task model.TerminalTask) {
	switch task.Name {
	case "kill_session":
		if ok := KillSession(task.Args); ok {
			//service.FinishTask(task.ID)
		}
	default:

	}
}

func KillSession(sessionID string) bool {
	if sw, ok := sessMap.Get(sessionID); ok {
		sw.Terminate()
		return true
	}
	return false
}

func GetAliveSessions() []string {
	//lock.RLock()
	//defer lock.RUnlock()
	//sids := make([]string, 0, len(sessionMap))
	//for sid := range sessionMap {
	//	sids = append(sids, sid)
	//}
	//
	return sessMap.Range()
}

//func GetAliveSessionCount() int {
//	lock.RLock()
//	defer lock.RUnlock()
//	return len(sessionMap)
//}

//func AddSession(sw Session) {
//	lock.Lock()
//	defer lock.Unlock()
//	sessionMap[sw.SessionID()] = sw
//}

//func postSession(data map[string]interface{}) bool {
//	for i := 0; i < 5; i++ {
//		if service.CreateSession(data) {
//			return true
//		}
//		time.Sleep(200 * time.Millisecond)
//	}
//	return false
//}

//func finishSession(data map[string]interface{}) {
//	service.FinishSession(data)
//}

//func CreateCommonSwitch(p proxyEngine) (s *commonSwitch, ok bool) {
//	s = NewCommonSwitch(p)
//	//ok = postSession(s.MapData())
//	if ok {
//		AddSession(s)
//	}
//	return s, ok
//}

func RemoveCommonSwitch(s *commonSwitch) {
	//lock.Lock()
	//defer lock.Unlock()
	//delete(sessionMap, s.ID)
	//finishSession(s.MapData())
	//logger.Infof("Session %s has finished", s.ID)
	sessMap.Delete(s.ID)
}

type sessionManager struct {
	data map[string]*commonSwitch
	sync.Mutex
}

func (s *sessionManager) Add(id string, sess *commonSwitch) {
	s.Lock()
	defer s.Unlock()
	s.data[id] = sess
}
func (s *sessionManager) Get(id string) (sess *commonSwitch, ok bool) {
	s.Lock()
	defer s.Unlock()
	sess, ok = s.data[id]
	return
}

func (s *sessionManager) Delete(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.data, id)
}

func (s *sessionManager) Range() []string {
	sids := make([]string, 0, len(s.data))
	s.Lock()
	defer s.Unlock()
	for sid := range s.data {
		sids = append(sids, sid)
	}
	return sids
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		data: make(map[string]*commonSwitch),
	}
}
