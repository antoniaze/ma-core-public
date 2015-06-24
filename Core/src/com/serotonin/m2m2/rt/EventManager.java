/*
    Copyright (C) 2014 Infinite Automation Systems Inc. All rights reserved.
    @author Matthew Lohbihler
 */
package com.serotonin.m2m2.rt;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.db.dao.EventDao;
import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.i18n.TranslatableMessage;
import com.serotonin.m2m2.module.EventManagerListenerDefinition;
import com.serotonin.m2m2.rt.event.AlarmLevels;
import com.serotonin.m2m2.rt.event.EventInstance;
import com.serotonin.m2m2.rt.event.UserEventCache;
import com.serotonin.m2m2.rt.event.UserEventListener;
import com.serotonin.m2m2.rt.event.handlers.EmailHandlerRT;
import com.serotonin.m2m2.rt.event.handlers.EventHandlerRT;
import com.serotonin.m2m2.rt.event.type.EventType;
import com.serotonin.m2m2.rt.event.type.SystemEventType;
import com.serotonin.m2m2.rt.maint.work.WorkItem;
import com.serotonin.m2m2.vo.User;
import com.serotonin.m2m2.vo.event.EventHandlerVO;
import com.serotonin.m2m2.vo.permission.Permissions;
import com.serotonin.util.ILifecycle;

/**
 * @author Matthew Lohbihler
 */
public class EventManager implements ILifecycle {
	private final Log log = LogFactory.getLog(EventManager.class);
	private static final int RECENT_EVENT_PERIOD = 1000 * 60 * 10; // 10
																	// minutes.

	private final List<EventManagerListenerDefinition> listeners = new CopyOnWriteArrayList<EventManagerListenerDefinition>();
	private final List<UserEventListener> userEventListeners = new CopyOnWriteArrayList<UserEventListener>();
	private final List<EventInstance> activeEvents = new CopyOnWriteArrayList<EventInstance>();
	private final List<EventInstance> recentEvents = new ArrayList<EventInstance>();
	private EventDao eventDao;
	private UserDao userDao;
	private long lastAlarmTimestamp = 0;
	private int highestActiveAlarmLevel = 0;

	//Cache for all active events for a logged in user, allow entries to remain un-accessed for 15 minutes and cleanup cache every minute
	private final UserEventCache userEventCache = new UserEventCache(15 * 60000,  60000);
	
	//
	//
	// Basic event management.
	//
	/**
	 * Raise Event 
	 * @param type
	 * @param time
	 * @param rtnApplicable - does this event return to normal?
	 * @param alarmLevel
	 * @param message
	 * @param context
	 */
	public void raiseEvent(EventType type, long time, boolean rtnApplicable,
			int alarmLevel, TranslatableMessage message,
			Map<String, Object> context) {
		
		// Check if there is an event for this type already active.
		EventInstance dup = get(type);
		if (dup != null) {
			// Check the duplicate handling.
			boolean discard = canDiscard(type, message);
			if (discard)
				return;

			// Otherwise we just continue...
		} else if (!rtnApplicable) {
			// Check if we've already seen this type recently.
			boolean recent = isRecent(type, message);
			if (recent)
				return;
		}

		// Determine if the event should be suppressed.
		TranslatableMessage autoAckMessage = null;
		for (EventManagerListenerDefinition l : listeners) {
			autoAckMessage = l.autoAckEventWithMessage(type);
			if (autoAckMessage != null)
				break;
		}

		EventInstance evt = new EventInstance(type, time, rtnApplicable,
				alarmLevel, message, context);

		if (autoAckMessage == null)
			setHandlers(evt);

		// Get id from database by inserting event immediately.
		//Check to see if we are Not Logging these
		if(alarmLevel != AlarmLevels.DO_NOT_LOG){
			eventDao.saveEvent(evt);
		}

		// Create user alarm records for all applicable users
		List<Integer> eventUserIds = new ArrayList<Integer>();
		Set<String> emailUsers = new HashSet<String>();

		for (User user : userDao.getActiveUsers()) {
			// Do not create an event for this user if the event type says the
			// user should be skipped.
			if (type.excludeUser(user))
				continue;

			if (Permissions.hasEventTypePermission(user, type)) {
				eventUserIds.add(user.getId());
				if (evt.isAlarm() && user.getReceiveAlarmEmails() > 0
						&& alarmLevel >= user.getReceiveAlarmEmails())
					emailUsers.add(user.getEmail());
			
				//Notify All User Event Listeners of the new event
				for(UserEventListener l : this.userEventListeners){
					if(l.getUserId() == user.getId()){
						Common.backgroundProcessing.addWorkItem(new EventNotifyWorkItem(user, l, evt, true, false, false, false));
					}
				}
			
				//Add to the UserEventCache if the user has recently accessed thier events
				this.userEventCache.addEvent(user.getId(), evt);
			}
			
		}

		if ((eventUserIds.size() > 0)&&(alarmLevel != AlarmLevels.DO_NOT_LOG)) {
			eventDao.insertUserEvents(evt.getId(), eventUserIds, evt.isAlarm());
			if (autoAckMessage == null && evt.isAlarm())
				lastAlarmTimestamp = System.currentTimeMillis();
		}

		if (evt.isRtnApplicable())
			activeEvents.add(evt);
		else if (evt.getEventType().isRateLimited()) {
			synchronized (emailUsers) {
				recentEvents.add(evt);
			}
		}

		if ((autoAckMessage != null)&&(alarmLevel != AlarmLevels.DO_NOT_LOG))
			this.acknowledgeEvent(evt, time, 0, autoAckMessage);
		else {
			if (evt.isRtnApplicable()) {
				if (alarmLevel > highestActiveAlarmLevel) {
					int oldValue = highestActiveAlarmLevel;
					highestActiveAlarmLevel = alarmLevel;
					SystemEventType
							.raiseEvent(
									new SystemEventType(
											SystemEventType.TYPE_MAX_ALARM_LEVEL_CHANGED),
									time,
									false,
									getAlarmLevelChangeMessage(
											"event.alarmMaxIncreased", oldValue));
				}
			}

			// Call raiseEvent handlers.
			handleRaiseEvent(evt, emailUsers);

			if (log.isDebugEnabled())
				log.debug("Event raised: type=" + type + ", message="
						+ message.translate(Common.getTranslations()));
		}
	}

	private boolean canDiscard(EventType type, TranslatableMessage message) {
		// Check the duplicate handling.
		int dh = type.getDuplicateHandling();
		if (dh == EventType.DuplicateHandling.DO_NOT_ALLOW) {
			// Create a log error...
			log.error("An event was raised for a type that is already active: type="
					+ type + ", message=" + message.getKey());
			// ... but ultimately just ignore the thing.
			return true;
		}

		if (dh == EventType.DuplicateHandling.IGNORE)
			// Safely return.
			return true;

		if (dh == EventType.DuplicateHandling.IGNORE_SAME_MESSAGE) {
			// Ignore only if the message is the same. There may be events of
			// this type with different messages,
			// so look through them all for a match.
			for (EventInstance e : getAll(type)) {
				if (e.getMessage().equals(message))
					return true;
			}
		}

		return false;
	}

	private boolean isRecent(EventType type, TranslatableMessage message) {
		long cutoff = System.currentTimeMillis() - RECENT_EVENT_PERIOD;
		// Iterate through the recent events list.
		synchronized (recentEvents) {
			for (int i = recentEvents.size() - 1; i >= 0; i--) {
				EventInstance evt = recentEvents.get(i);
				// This method also purges the list, so we need to check if the
				// event instance has expired or not.
				if (cutoff > evt.getActiveTimestamp())
					recentEvents.remove(i);
				else if (evt.getEventType().equals(type)
						&& evt.getMessage().equals(message))
					return true;
			}
		}
		return false;
	}

	public void returnToNormal(EventType type, long time) {
		returnToNormal(type, time, EventInstance.RtnCauses.RETURN_TO_NORMAL);
	}

	public void returnToNormal(EventType type, long time, int cause) {
		EventInstance evt = remove(type);
		
		// Loop in case of multiples
		while (evt != null) {

			for (User user : userDao.getActiveUsers()) {
				// Do not create an event for this user if the event type says the
				// user should be skipped.
				if (type.excludeUser(user))
					continue;
	
				if (Permissions.hasEventTypePermission(user, type)) {
					//Notify All User Event Listeners of the new event
					for(UserEventListener l : this.userEventListeners){
						if(l.getUserId() == user.getId()){
							Common.backgroundProcessing.addWorkItem(new EventNotifyWorkItem(user, l, evt, false, true, false, false));
	
						}
					}
					this.userEventCache.updateEvent(user.getId(), evt);
				}
				
			}
			
			resetHighestAlarmLevel(time);

			evt.returnToNormal(time, cause);
			if(evt.getAlarmLevel() != AlarmLevels.DO_NOT_LOG)
				eventDao.saveEvent(evt);

			// Call inactiveEvent handlers.
			handleInactiveEvent(evt);

			// Check for another
			evt = remove(type);
		}

		if (log.isTraceEnabled())
			log.trace("Event returned to normal: type=" + type);
	}

	private void deactivateEvent(EventInstance evt, long time, int inactiveCause) {
		activeEvents.remove(evt);
		resetHighestAlarmLevel(time);
		evt.returnToNormal(time, inactiveCause);
		eventDao.saveEvent(evt);


		for (User user : userDao.getActiveUsers()) {
			// Do not create an event for this user if the event type says the
			// user should be skipped.
			if (evt.getEventType().excludeUser(user))
				continue;

			if (Permissions.hasEventTypePermission(user, evt.getEventType())) {
				//Notify All User Event Listeners of the new event
				for(UserEventListener l : this.userEventListeners){
					if(l.getUserId() == user.getId()){
						Common.backgroundProcessing.addWorkItem(new EventNotifyWorkItem(user, l, evt, false, false, true, false));
					}
				}
			
			}
			this.userEventCache.removeEvent(user.getId(), evt);
		}
		
		// Call inactiveEvent handlers.
		handleInactiveEvent(evt);
	}
	
	/**
	 * Added to allow Acknowledge Events to be fired
	 * @param evt
	 * @param time
	 * @param userId
	 * @param alternateAckSource
	 */
	public void acknowledgeEvent(EventInstance evt, long time, int userId, TranslatableMessage alternateAckSource){
		eventDao.ackEvent(evt.getId(), time, userId, alternateAckSource);
		//Fill in the info if someone on the other end wants it
		evt.setAcknowledgedByUserId(userId);
		evt.setAcknowledgedTimestamp(time);
		evt.setAlternateAckSource(alternateAckSource);
		

		User user = userDao.getUser(userId);
		if(user.isDisabled())
			return;
		// Do not create an event for this user if the event type says the
		// user should be skipped.
		if (evt.getEventType().excludeUser(user))
			return;

		if (Permissions.hasEventTypePermission(user, evt.getEventType())) {
			//Notify All User Event Listeners of the new event
			for(UserEventListener l : this.userEventListeners){
				if(l.getUserId() == user.getId()){
					Common.backgroundProcessing.addWorkItem(new EventNotifyWorkItem(user, l, evt, false, false, false, true));
				}
			}
		this.userEventCache.removeEvent(userId, evt);

		}
	}

	public long getLastAlarmTimestamp() {
		return lastAlarmTimestamp;
	}

	//
	//
	// Canceling events.
	//
	public void cancelEventsForDataPoint(int dataPointId) {
		for (EventInstance e : activeEvents) {
			if (e.getEventType().getDataPointId() == dataPointId)
				deactivateEvent(e, System.currentTimeMillis(),
						EventInstance.RtnCauses.SOURCE_DISABLED);
		}

		synchronized (recentEvents) {
			for (int i = recentEvents.size() - 1; i >= 0; i--) {
				EventInstance e = recentEvents.get(i);
				if (e.getEventType().getDataPointId() == dataPointId)
					recentEvents.remove(i);
			}
		}
	}

	public void cancelEventsForDataSource(int dataSourceId) {
		for (EventInstance e : activeEvents) {
			if (e.getEventType().getDataSourceId() == dataSourceId)
				deactivateEvent(e, System.currentTimeMillis(),
						EventInstance.RtnCauses.SOURCE_DISABLED);
		}

		synchronized (recentEvents) {
			for (int i = recentEvents.size() - 1; i >= 0; i--) {
				EventInstance e = recentEvents.get(i);
				if (e.getEventType().getDataSourceId() == dataSourceId)
					recentEvents.remove(i);
			}
		}
	}

	public void cancelEventsForPublisher(int publisherId) {
		for (EventInstance e : activeEvents) {
			if (e.getEventType().getPublisherId() == publisherId)
				deactivateEvent(e, System.currentTimeMillis(),
						EventInstance.RtnCauses.SOURCE_DISABLED);
		}

		synchronized (recentEvents) {
			for (int i = recentEvents.size() - 1; i >= 0; i--) {
				EventInstance e = recentEvents.get(i);
				if (e.getEventType().getPublisherId() == publisherId)
					recentEvents.remove(i);
			}
		}
	}

	private void resetHighestAlarmLevel(long time) {
		int max = 0;
		for (EventInstance e : activeEvents) {
			if (e.getAlarmLevel() > max)
				max = e.getAlarmLevel();
		}

		if (max > highestActiveAlarmLevel) {
			int oldValue = highestActiveAlarmLevel;
			highestActiveAlarmLevel = max;
			SystemEventType.raiseEvent(
					new SystemEventType(
							SystemEventType.TYPE_MAX_ALARM_LEVEL_CHANGED),
					time,
					false,
					getAlarmLevelChangeMessage("event.alarmMaxIncreased",
							oldValue));
		} else if (max < highestActiveAlarmLevel) {
			int oldValue = highestActiveAlarmLevel;
			highestActiveAlarmLevel = max;
			SystemEventType.raiseEvent(
					new SystemEventType(
							SystemEventType.TYPE_MAX_ALARM_LEVEL_CHANGED),
					time,
					false,
					getAlarmLevelChangeMessage("event.alarmMaxDecreased",
							oldValue));
		}
	}

	private TranslatableMessage getAlarmLevelChangeMessage(String key,
			int oldValue) {
		return new TranslatableMessage(key,
				AlarmLevels.getAlarmLevelMessage(oldValue),
				AlarmLevels.getAlarmLevelMessage(highestActiveAlarmLevel));
	}

	//
	//
	// Lifecycle interface
	//
	@Override
	public void initialize() {
		eventDao = new EventDao();
		userDao = new UserDao();

		// Get all active events from the database.
		activeEvents.addAll(eventDao.getActiveEvents());
		lastAlarmTimestamp = System.currentTimeMillis();
		resetHighestAlarmLevel(lastAlarmTimestamp);
	}

	@Override
	public void terminate() {
		// no op
	}

	@Override
	public void joinTermination() {
		// no op
	}

	//
	//
	// Listeners
	//
	public void addListener(EventManagerListenerDefinition l) {
		listeners.add(l);
	}

	public void removeListener(EventManagerListenerDefinition l) {
		listeners.remove(l);
	}
	public void addUserEventListener(UserEventListener l){
		userEventListeners.add(l);
	}
	public void removeUserEventListener(UserEventListener l){
		userEventListeners.remove(l);
	}

	//
	// User Event Cache Access
	//
	public List<EventInstance> getAllActiveUserEvents(int userId){
		return this.userEventCache.getAllEvents(userId);
	}

	
	//
	//
	// Convenience
	//
	/**
	 * Returns the first event instance with the given type, or null is there is
	 * none.
	 */
	private EventInstance get(EventType type) {
		for (EventInstance e : activeEvents) {
			if (e.getEventType().equals(type))
				return e;
		}
		return null;
	}

	private List<EventInstance> getAll(EventType type) {
		List<EventInstance> result = new ArrayList<EventInstance>();
		for (EventInstance e : activeEvents) {
			if (e.getEventType().equals(type))
				result.add(e);
		}
		return result;
	}

	/**
	 * To access all active events quickly
	 * @param type
	 * @return
	 */
	public List<EventInstance> getAllActive() {
		List<EventInstance> result = new ArrayList<EventInstance>();
		for (EventInstance e : activeEvents) {
				result.add(e);
		}
		return result;
	}
	
	/**
	 * Finds and removes the first event instance with the given type. Returns
	 * null if there is none.
	 * 
	 * @param type
	 * @return
	 */
	private EventInstance remove(EventType type) {
		for (EventInstance e : activeEvents) {
			if (e.getEventType().equals(type)) {
				activeEvents.remove(e);
				return e;
			}
		}
		return null;
	}

	private void setHandlers(EventInstance evt) {
		List<EventHandlerVO> vos = eventDao
				.getEventHandlers(evt.getEventType());
		List<EventHandlerRT> rts = null;
		for (EventHandlerVO vo : vos) {
			if (!vo.isDisabled()) {
				if (rts == null)
					rts = new ArrayList<EventHandlerRT>();
				rts.add(vo.createRuntime());
			}
		}
		if (rts != null)
			evt.setHandlers(rts);
	}

	private void handleRaiseEvent(EventInstance evt,
			Set<String> defaultAddresses) {
		if (evt.getHandlers() != null) {
			for (EventHandlerRT h : evt.getHandlers()) {
				h.eventRaised(evt);

				// If this is an email handler, remove any addresses to which it
				// was sent from the default addresses
				// so that the default users do not receive multiple
				// notifications.
				if (h instanceof EmailHandlerRT) {
					for (String addr : ((EmailHandlerRT) h)
							.getActiveRecipients())
						defaultAddresses.remove(addr);
				}
			}
		}

		if (!defaultAddresses.isEmpty()) {
			// If there are still any addresses left in the list, send them the
			// notification.
			EmailHandlerRT.sendActiveEmail(evt, defaultAddresses);
		}
	}

	private void handleInactiveEvent(EventInstance evt) {
		if (evt.getHandlers() != null) {
			for (EventHandlerRT h : evt.getHandlers())
				h.eventInactive(evt);
		}
	}
	
	
    class EventNotifyWorkItem implements WorkItem {

    	private final User user;
    	private final UserEventListener listener;
    	private final EventInstance event;
    	private final boolean raised;
    	private final boolean returnToNormal;
    	private final boolean deactivated;
    	private final boolean acknowledged;

        EventNotifyWorkItem(User user, UserEventListener listener, EventInstance event, boolean raised, 
        		boolean returnToNormal, boolean deactivated, boolean acknowledged) {
        	this.user = user;
            this.listener = listener;
            this.event = event;
            this.raised = raised;
            this.returnToNormal = returnToNormal;
            this.deactivated = deactivated;
            this.acknowledged = acknowledged;
            
        }

        @Override
        public void execute() {
        	
        	if(raised)
        		listener.raised(event);
        	else if(returnToNormal)
        		listener.returnToNormal(event);
        	else if(deactivated)
        		listener.deactivated(event);
        	else if(acknowledged)
        		listener.acknowledged(event);
        }

        @Override
        public int getPriority() {
            return WorkItem.PRIORITY_LOW;
        }

		/* (non-Javadoc)
		 * @see com.serotonin.m2m2.rt.maint.work.WorkItem#getDescription()
		 */
		@Override
		public String getDescription() {
			String type = "";
			if(raised)
				type = "raised";
			else if(deactivated)
				type = "deactivated";
			else if(returnToNormal)
				type = "return to normal";
			return "Event " + type + " Notification for user: " + user.getUsername() ;
		}
    }
}
